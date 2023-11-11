package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Properties;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.utils.Utils;

public class CtrCryptoInputStream extends CryptoInputStream {
  private long streamOffset = 0L;
  
  private final byte[] initIV;
  
  private final byte[] iv;
  
  private byte padding;
  
  private boolean cipherReset = false;
  
  public CtrCryptoInputStream(Properties properties, InputStream inputStream, byte[] key, byte[] iv) throws IOException {
    this(properties, inputStream, key, iv, 0L);
  }
  
  public CtrCryptoInputStream(Properties properties, ReadableByteChannel channel, byte[] key, byte[] iv) throws IOException {
    this(properties, channel, key, iv, 0L);
  }
  
  protected CtrCryptoInputStream(InputStream inputStream, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(inputStream, cipher, bufferSize, key, iv, 0L);
  }
  
  protected CtrCryptoInputStream(ReadableByteChannel channel, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(channel, cipher, bufferSize, key, iv, 0L);
  }
  
  protected CtrCryptoInputStream(Input input, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(input, cipher, bufferSize, key, iv, 0L);
  }
  
  public CtrCryptoInputStream(Properties properties, InputStream inputStream, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(inputStream, Utils.getCipherInstance("AES/CTR/NoPadding", properties), 
        
        CryptoInputStream.getBufferSize(properties), key, iv, streamOffset);
  }
  
  public CtrCryptoInputStream(Properties properties, ReadableByteChannel in, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(in, Utils.getCipherInstance("AES/CTR/NoPadding", properties), 
        
        CryptoInputStream.getBufferSize(properties), key, iv, streamOffset);
  }
  
  protected CtrCryptoInputStream(InputStream inputStream, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new StreamInput(inputStream, bufferSize), cipher, bufferSize, key, iv, streamOffset);
  }
  
  protected CtrCryptoInputStream(ReadableByteChannel channel, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new ChannelInput(channel), cipher, bufferSize, key, iv, streamOffset);
  }
  
  protected CtrCryptoInputStream(Input input, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    super(input, cipher, bufferSize, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    this.initIV = (byte[])iv.clone();
    this.iv = (byte[])iv.clone();
    CryptoInputStream.checkStreamCipher(cipher);
    resetStreamOffset(streamOffset);
  }
  
  public long skip(long n) throws IOException {
    Utils.checkArgument((n >= 0L), "Negative skip length.");
    checkStream();
    if (n == 0L)
      return 0L; 
    if (n <= this.outBuffer.remaining()) {
      int i = this.outBuffer.position() + (int)n;
      this.outBuffer.position(i);
      return n;
    } 
    n -= this.outBuffer.remaining();
    long skipped = this.input.skip(n);
    if (skipped < 0L)
      skipped = 0L; 
    long pos = this.streamOffset + skipped;
    skipped += this.outBuffer.remaining();
    resetStreamOffset(pos);
    return skipped;
  }
  
  public int read(ByteBuffer buf) throws IOException {
    checkStream();
    int unread = this.outBuffer.remaining();
    if (unread <= 0) {
      int n = this.input.read(this.inBuffer);
      if (n <= 0)
        return n; 
      this.streamOffset += n;
      if (buf.isDirect() && buf.remaining() >= this.inBuffer.position() && this.padding == 0) {
        decryptInPlace(buf);
        this.padding = postDecryption(this.streamOffset);
        return n;
      } 
      decrypt();
      this.padding = postDecryption(this.streamOffset);
    } 
    unread = this.outBuffer.remaining();
    int toRead = buf.remaining();
    if (toRead <= unread) {
      int limit = this.outBuffer.limit();
      this.outBuffer.limit(this.outBuffer.position() + toRead);
      buf.put(this.outBuffer);
      this.outBuffer.limit(limit);
      return toRead;
    } 
    buf.put(this.outBuffer);
    return unread;
  }
  
  public void seek(long position) throws IOException {
    Utils.checkArgument((position >= 0L), "Cannot seek to negative offset.");
    checkStream();
    if (position >= getStreamPosition() && position <= getStreamOffset()) {
      int forward = (int)(position - getStreamPosition());
      if (forward > 0)
        this.outBuffer.position(this.outBuffer.position() + forward); 
    } else {
      this.input.seek(position);
      resetStreamOffset(position);
    } 
  }
  
  protected long getStreamOffset() {
    return this.streamOffset;
  }
  
  protected void setStreamOffset(long streamOffset) {
    this.streamOffset = streamOffset;
  }
  
  protected long getStreamPosition() {
    return this.streamOffset - this.outBuffer.remaining();
  }
  
  protected int decryptMore() throws IOException {
    int n = this.input.read(this.inBuffer);
    if (n <= 0)
      return n; 
    this.streamOffset += n;
    decrypt();
    this.padding = postDecryption(this.streamOffset);
    return this.outBuffer.remaining();
  }
  
  protected void decrypt() throws IOException {
    Utils.checkState((this.inBuffer.position() >= this.padding));
    if (this.inBuffer.position() == this.padding)
      return; 
    this.inBuffer.flip();
    this.outBuffer.clear();
    decryptBuffer(this.outBuffer);
    this.inBuffer.clear();
    this.outBuffer.flip();
    if (this.padding > 0)
      this.outBuffer.position(this.padding); 
  }
  
  protected void decryptInPlace(ByteBuffer buf) throws IOException {
    Utils.checkState((this.inBuffer.position() >= this.padding));
    Utils.checkState(buf.isDirect());
    Utils.checkState((buf.remaining() >= this.inBuffer.position()));
    Utils.checkState((this.padding == 0));
    if (this.inBuffer.position() == this.padding)
      return; 
    this.inBuffer.flip();
    decryptBuffer(buf);
    this.inBuffer.clear();
  }
  
  protected void decrypt(ByteBuffer buf, int offset, int len) throws IOException {
    int pos = buf.position();
    int limit = buf.limit();
    int n = 0;
    while (n < len) {
      buf.position(offset + n);
      buf.limit(offset + n + Math.min(len - n, this.inBuffer.remaining()));
      this.inBuffer.put(buf);
      try {
        decrypt();
        buf.position(offset + n);
        buf.limit(limit);
        n += this.outBuffer.remaining();
        buf.put(this.outBuffer);
      } finally {
        this.padding = postDecryption(this.streamOffset - (len - n));
      } 
    } 
    buf.position(pos);
  }
  
  protected byte postDecryption(long position) throws IOException {
    byte padding = 0;
    if (this.cipherReset) {
      resetCipher(position);
      padding = getPadding(position);
      this.inBuffer.position(padding);
    } 
    return padding;
  }
  
  protected byte[] getInitIV() {
    return this.initIV;
  }
  
  protected long getCounter(long position) {
    return position / this.cipher.getBlockSize();
  }
  
  protected byte getPadding(long position) {
    return (byte)(int)(position % this.cipher.getBlockSize());
  }
  
  protected void initCipher() {}
  
  protected void resetCipher(long position) throws IOException {
    long counter = getCounter(position);
    calculateIV(this.initIV, counter, this.iv);
    try {
      this.cipher.init(2, this.key, new IvParameterSpec(this.iv));
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
    this.cipherReset = false;
  }
  
  protected void resetStreamOffset(long offset) throws IOException {
    this.streamOffset = offset;
    this.inBuffer.clear();
    this.outBuffer.clear();
    this.outBuffer.limit(0);
    resetCipher(offset);
    this.padding = getPadding(offset);
    this.inBuffer.position(this.padding);
  }
  
  protected void decryptBuffer(ByteBuffer out) throws IOException {
    int inputSize = this.inBuffer.remaining();
    try {
      int n = this.cipher.update(this.inBuffer, out);
      if (n < inputSize) {
        this.cipher.doFinal(this.inBuffer, out);
        this.cipherReset = true;
      } 
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
  }
  
  static void calculateIV(byte[] initIV, long counter, byte[] IV) {
    Utils.checkArgument((initIV.length == 16));
    Utils.checkArgument((IV.length == 16));
    int i = IV.length;
    int j = 0;
    int sum = 0;
    while (i-- > 0) {
      sum = (initIV[i] & 0xFF) + (sum >>> 8);
      if (j++ < 8) {
        sum += (byte)(int)counter & 0xFF;
        counter >>>= 8L;
      } 
      IV[i] = (byte)sum;
    } 
  }
}
