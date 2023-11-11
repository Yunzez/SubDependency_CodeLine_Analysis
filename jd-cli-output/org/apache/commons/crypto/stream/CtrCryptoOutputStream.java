package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.util.Properties;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.stream.output.Output;
import org.apache.commons.crypto.stream.output.StreamOutput;
import org.apache.commons.crypto.utils.Utils;

public class CtrCryptoOutputStream extends CryptoOutputStream {
  private long streamOffset = 0L;
  
  private final byte[] initIV;
  
  private final byte[] iv;
  
  private byte padding;
  
  private boolean cipherReset = false;
  
  public CtrCryptoOutputStream(Properties props, OutputStream out, byte[] key, byte[] iv) throws IOException {
    this(props, out, key, iv, 0L);
  }
  
  public CtrCryptoOutputStream(Properties props, WritableByteChannel out, byte[] key, byte[] iv) throws IOException {
    this(props, out, key, iv, 0L);
  }
  
  protected CtrCryptoOutputStream(OutputStream out, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(out, cipher, bufferSize, key, iv, 0L);
  }
  
  protected CtrCryptoOutputStream(WritableByteChannel channel, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(channel, cipher, bufferSize, key, iv, 0L);
  }
  
  protected CtrCryptoOutputStream(Output output, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv) throws IOException {
    this(output, cipher, bufferSize, key, iv, 0L);
  }
  
  public CtrCryptoOutputStream(Properties properties, OutputStream outputStream, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(outputStream, Utils.getCipherInstance("AES/CTR/NoPadding", properties), 
        
        CryptoInputStream.getBufferSize(properties), key, iv, streamOffset);
  }
  
  public CtrCryptoOutputStream(Properties properties, WritableByteChannel channel, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(channel, Utils.getCipherInstance("AES/CTR/NoPadding", properties), 
        
        CryptoInputStream.getBufferSize(properties), key, iv, streamOffset);
  }
  
  protected CtrCryptoOutputStream(OutputStream outputStream, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new StreamOutput(outputStream, bufferSize), cipher, bufferSize, key, iv, streamOffset);
  }
  
  protected CtrCryptoOutputStream(WritableByteChannel channel, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(new ChannelOutput(channel), cipher, bufferSize, key, iv, streamOffset);
  }
  
  protected CtrCryptoOutputStream(Output output, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    super(output, cipher, bufferSize, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
    CryptoInputStream.checkStreamCipher(cipher);
    this.streamOffset = streamOffset;
    this.initIV = (byte[])iv.clone();
    this.iv = (byte[])iv.clone();
    resetCipher();
  }
  
  protected void encrypt() throws IOException {
    Utils.checkState((this.inBuffer.position() >= this.padding));
    if (this.inBuffer.position() == this.padding)
      return; 
    this.inBuffer.flip();
    this.outBuffer.clear();
    encryptBuffer(this.outBuffer);
    this.inBuffer.clear();
    this.outBuffer.flip();
    if (this.padding > 0) {
      this.outBuffer.position(this.padding);
      this.padding = 0;
    } 
    int len = this.output.write(this.outBuffer);
    this.streamOffset += len;
    if (this.cipherReset)
      resetCipher(); 
  }
  
  protected void encryptFinal() throws IOException {
    encrypt();
  }
  
  protected void initCipher() {}
  
  private void resetCipher() throws IOException {
    long counter = this.streamOffset / this.cipher.getBlockSize();
    this.padding = (byte)(int)(this.streamOffset % this.cipher.getBlockSize());
    this.inBuffer.position(this.padding);
    CtrCryptoInputStream.calculateIV(this.initIV, counter, this.iv);
    try {
      this.cipher.init(1, this.key, new IvParameterSpec(this.iv));
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
    this.cipherReset = false;
  }
  
  private void encryptBuffer(ByteBuffer out) throws IOException {
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
  
  protected long getStreamOffset() {
    return this.streamOffset;
  }
  
  protected void setStreamOffset(long streamOffset) {
    this.streamOffset = streamOffset;
  }
}
