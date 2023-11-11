package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;
import javax.crypto.ShortBufferException;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.output.ChannelOutput;
import org.apache.commons.crypto.stream.output.Output;
import org.apache.commons.crypto.stream.output.StreamOutput;
import org.apache.commons.crypto.utils.Utils;

public class CryptoOutputStream extends OutputStream implements WritableByteChannel {
  private final byte[] oneByteBuf = new byte[1];
  
  final Output output;
  
  final CryptoCipher cipher;
  
  private final int bufferSize;
  
  final Key key;
  
  private final AlgorithmParameterSpec params;
  
  private boolean closed;
  
  ByteBuffer inBuffer;
  
  ByteBuffer outBuffer;
  
  public CryptoOutputStream(String transformation, Properties properties, OutputStream outputStream, Key key, AlgorithmParameterSpec params) throws IOException {
    this(outputStream, Utils.getCipherInstance(transformation, properties), 
        CryptoInputStream.getBufferSize(properties), key, params);
  }
  
  public CryptoOutputStream(String transformation, Properties properties, WritableByteChannel out, Key key, AlgorithmParameterSpec params) throws IOException {
    this(out, Utils.getCipherInstance(transformation, properties), 
        CryptoInputStream.getBufferSize(properties), key, params);
  }
  
  protected CryptoOutputStream(OutputStream outputStream, CryptoCipher cipher, int bufferSize, Key key, AlgorithmParameterSpec params) throws IOException {
    this(new StreamOutput(outputStream, bufferSize), cipher, bufferSize, key, params);
  }
  
  protected CryptoOutputStream(WritableByteChannel channel, CryptoCipher cipher, int bufferSize, Key key, AlgorithmParameterSpec params) throws IOException {
    this(new ChannelOutput(channel), cipher, bufferSize, key, params);
  }
  
  protected CryptoOutputStream(Output output, CryptoCipher cipher, int bufferSize, Key key, AlgorithmParameterSpec params) throws IOException {
    this.output = output;
    this.bufferSize = CryptoInputStream.checkBufferSize(cipher, bufferSize);
    this.cipher = cipher;
    this.key = key;
    this.params = params;
    if (!(params instanceof javax.crypto.spec.IvParameterSpec))
      throw new IOException("Illegal parameters"); 
    this.inBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    this.outBuffer = ByteBuffer.allocateDirect(this.bufferSize + cipher
        .getBlockSize());
    initCipher();
  }
  
  public void write(int b) throws IOException {
    this.oneByteBuf[0] = (byte)(b & 0xFF);
    write(this.oneByteBuf, 0, this.oneByteBuf.length);
  }
  
  public void write(byte[] array, int off, int len) throws IOException {
    checkStream();
    Objects.requireNonNull(array, "array");
    if (off < 0 || len < 0 || off > array.length || len > array.length - off)
      throw new IndexOutOfBoundsException(); 
    while (len > 0) {
      int remaining = this.inBuffer.remaining();
      if (len < remaining) {
        this.inBuffer.put(array, off, len);
        len = 0;
        continue;
      } 
      this.inBuffer.put(array, off, remaining);
      off += remaining;
      len -= remaining;
      encrypt();
    } 
  }
  
  public void flush() throws IOException {
    checkStream();
    encrypt();
    this.output.flush();
    super.flush();
  }
  
  public void close() throws IOException {
    if (this.closed)
      return; 
    try {
      encryptFinal();
      this.output.close();
      freeBuffers();
      this.cipher.close();
      super.close();
    } finally {
      this.closed = true;
    } 
  }
  
  public boolean isOpen() {
    return !this.closed;
  }
  
  public int write(ByteBuffer src) throws IOException {
    checkStream();
    int len = src.remaining();
    int remaining = len;
    while (remaining > 0) {
      int space = this.inBuffer.remaining();
      if (remaining < space) {
        this.inBuffer.put(src);
        remaining = 0;
        continue;
      } 
      int oldLimit = src.limit();
      int newLimit = src.position() + space;
      src.limit(newLimit);
      this.inBuffer.put(src);
      src.limit(oldLimit);
      remaining -= space;
      encrypt();
    } 
    return len;
  }
  
  protected void initCipher() throws IOException {
    try {
      this.cipher.init(1, this.key, this.params);
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
  }
  
  protected void encrypt() throws IOException {
    this.inBuffer.flip();
    this.outBuffer.clear();
    try {
      this.cipher.update(this.inBuffer, this.outBuffer);
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } 
    this.inBuffer.clear();
    this.outBuffer.flip();
    while (this.outBuffer.hasRemaining())
      this.output.write(this.outBuffer); 
  }
  
  protected void encryptFinal() throws IOException {
    this.inBuffer.flip();
    this.outBuffer.clear();
    try {
      this.cipher.doFinal(this.inBuffer, this.outBuffer);
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
    this.inBuffer.clear();
    this.outBuffer.flip();
    while (this.outBuffer.hasRemaining())
      this.output.write(this.outBuffer); 
  }
  
  protected void checkStream() throws IOException {
    if (this.closed)
      throw new IOException("Stream closed"); 
  }
  
  protected void freeBuffers() {
    CryptoInputStream.freeDirectBuffer(this.inBuffer);
    CryptoInputStream.freeDirectBuffer(this.outBuffer);
  }
  
  protected ByteBuffer getOutBuffer() {
    return this.outBuffer;
  }
  
  protected CryptoCipher getCipher() {
    return this.cipher;
  }
  
  protected int getBufferSize() {
    return this.bufferSize;
  }
  
  protected ByteBuffer getInBuffer() {
    return this.inBuffer;
  }
}
