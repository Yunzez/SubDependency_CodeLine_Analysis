package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.utils.IoUtils;
import org.apache.commons.crypto.utils.Utils;

public class PositionedCryptoInputStream extends CtrCryptoInputStream {
  private final Queue<ByteBuffer> bufferPool = new ConcurrentLinkedQueue<>();
  
  private final Queue<CipherState> cipherPool = new ConcurrentLinkedQueue<>();
  
  private final Properties properties;
  
  public PositionedCryptoInputStream(Properties properties, Input in, byte[] key, byte[] iv, long streamOffset) throws IOException {
    this(properties, in, Utils.getCipherInstance("AES/CTR/NoPadding", properties), 
        CryptoInputStream.getBufferSize(properties), key, iv, streamOffset);
  }
  
  protected PositionedCryptoInputStream(Properties properties, Input input, CryptoCipher cipher, int bufferSize, byte[] key, byte[] iv, long streamOffset) throws IOException {
    super(input, cipher, bufferSize, key, iv, streamOffset);
    this.properties = properties;
  }
  
  public int read(long position, byte[] buffer, int offset, int length) throws IOException {
    checkStream();
    int n = this.input.read(position, buffer, offset, length);
    if (n > 0)
      decrypt(position, buffer, offset, n); 
    return n;
  }
  
  public void readFully(long position, byte[] buffer, int offset, int length) throws IOException {
    checkStream();
    IoUtils.readFully(this.input, position, buffer, offset, length);
    if (length > 0)
      decrypt(position, buffer, offset, length); 
  }
  
  public void readFully(long position, byte[] buffer) throws IOException {
    readFully(position, buffer, 0, buffer.length);
  }
  
  protected void decrypt(long position, byte[] buffer, int offset, int length) throws IOException {
    ByteBuffer inByteBuffer = getBuffer();
    ByteBuffer outByteBuffer = getBuffer();
    CipherState state = null;
    try {
      state = getCipherState();
      byte[] iv = (byte[])getInitIV().clone();
      resetCipher(state, position, iv);
      byte padding = getPadding(position);
      inByteBuffer.position(padding);
      int n = 0;
      while (n < length) {
        int toDecrypt = Math.min(length - n, inByteBuffer.remaining());
        inByteBuffer.put(buffer, offset + n, toDecrypt);
        decrypt(state, inByteBuffer, outByteBuffer, padding);
        outByteBuffer.get(buffer, offset + n, toDecrypt);
        n += toDecrypt;
        padding = postDecryption(state, inByteBuffer, position + n, iv);
      } 
    } finally {
      returnBuffer(inByteBuffer);
      returnBuffer(outByteBuffer);
      returnCipherState(state);
    } 
  }
  
  private void decrypt(CipherState state, ByteBuffer inByteBuffer, ByteBuffer outByteBuffer, byte padding) throws IOException {
    Utils.checkState((inByteBuffer.position() >= padding));
    if (inByteBuffer.position() == padding)
      return; 
    inByteBuffer.flip();
    outByteBuffer.clear();
    decryptBuffer(state, inByteBuffer, outByteBuffer);
    inByteBuffer.clear();
    outByteBuffer.flip();
    if (padding > 0)
      outByteBuffer.position(padding); 
  }
  
  private void decryptBuffer(CipherState state, ByteBuffer inByteBuffer, ByteBuffer outByteBuffer) throws IOException {
    int inputSize = inByteBuffer.remaining();
    try {
      int n = state.getCryptoCipher().update(inByteBuffer, outByteBuffer);
      if (n < inputSize) {
        state.getCryptoCipher().doFinal(inByteBuffer, outByteBuffer);
        state.reset(true);
      } 
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
  }
  
  private byte postDecryption(CipherState state, ByteBuffer inByteBuffer, long position, byte[] iv) throws IOException {
    byte padding = 0;
    if (state.isReset()) {
      resetCipher(state, position, iv);
      padding = getPadding(position);
      inByteBuffer.position(padding);
    } 
    return padding;
  }
  
  private void resetCipher(CipherState state, long position, byte[] iv) throws IOException {
    long counter = getCounter(position);
    CtrCryptoInputStream.calculateIV(getInitIV(), counter, iv);
    try {
      state.getCryptoCipher().init(2, this.key, new IvParameterSpec(iv));
    } catch (GeneralSecurityException generalSecurityException) {}
    state.reset(false);
  }
  
  private CipherState getCipherState() throws IOException {
    CipherState state = this.cipherPool.poll();
    if (state == null) {
      CryptoCipher cryptoCipher;
      try {
        cryptoCipher = CryptoCipherFactory.getCryptoCipher("AES/CTR/NoPadding", this.properties);
      } catch (GeneralSecurityException e) {
        throw new IOException(e);
      } 
      state = new CipherState(cryptoCipher);
    } 
    return state;
  }
  
  private void returnCipherState(CipherState state) {
    if (state != null)
      this.cipherPool.add(state); 
  }
  
  private ByteBuffer getBuffer() {
    ByteBuffer buffer = this.bufferPool.poll();
    if (buffer == null)
      buffer = ByteBuffer.allocateDirect(getBufferSize()); 
    return buffer;
  }
  
  private void returnBuffer(ByteBuffer buf) {
    if (buf != null) {
      buf.clear();
      this.bufferPool.add(buf);
    } 
  }
  
  public void close() throws IOException {
    if (!isOpen())
      return; 
    cleanBufferPool();
    super.close();
  }
  
  private void cleanBufferPool() {
    ByteBuffer buf;
    while ((buf = this.bufferPool.poll()) != null)
      CryptoInputStream.freeDirectBuffer(buf); 
  }
  
  private static class CipherState {
    private final CryptoCipher cryptoCipher;
    
    private boolean reset;
    
    public CipherState(CryptoCipher cipher) {
      this.cryptoCipher = cipher;
      this.reset = false;
    }
    
    public CryptoCipher getCryptoCipher() {
      return this.cryptoCipher;
    }
    
    public boolean isReset() {
      return this.reset;
    }
    
    public void reset(boolean reset) {
      this.reset = reset;
    }
  }
}
