package org.apache.commons.crypto.stream;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.stream.input.ChannelInput;
import org.apache.commons.crypto.stream.input.Input;
import org.apache.commons.crypto.stream.input.StreamInput;
import org.apache.commons.crypto.utils.Utils;

public class CryptoInputStream extends InputStream implements ReadableByteChannel {
  private final byte[] oneByteBuf = new byte[1];
  
  public static final String STREAM_BUFFER_SIZE_KEY = "commons.crypto.stream.buffer.size";
  
  final CryptoCipher cipher;
  
  private final int bufferSize;
  
  final Key key;
  
  private final AlgorithmParameterSpec params;
  
  private boolean closed;
  
  private boolean finalDone = false;
  
  Input input;
  
  ByteBuffer inBuffer;
  
  ByteBuffer outBuffer;
  
  private static final int STREAM_BUFFER_SIZE_DEFAULT = 8192;
  
  private static final int MIN_BUFFER_SIZE = 512;
  
  public CryptoInputStream(String transformation, Properties properties, InputStream inputStream, Key key, AlgorithmParameterSpec params) throws IOException {
    this(inputStream, Utils.getCipherInstance(transformation, properties), 
        getBufferSize(properties), key, params);
  }
  
  public CryptoInputStream(String transformation, Properties properties, ReadableByteChannel channel, Key key, AlgorithmParameterSpec params) throws IOException {
    this(channel, Utils.getCipherInstance(transformation, properties), 
        getBufferSize(properties), key, params);
  }
  
  protected CryptoInputStream(InputStream inputStream, CryptoCipher cipher, int bufferSize, Key key, AlgorithmParameterSpec params) throws IOException {
    this(new StreamInput(inputStream, bufferSize), cipher, bufferSize, key, params);
  }
  
  protected CryptoInputStream(ReadableByteChannel channel, CryptoCipher cipher, int bufferSize, Key key, AlgorithmParameterSpec params) throws IOException {
    this(new ChannelInput(channel), cipher, bufferSize, key, params);
  }
  
  protected CryptoInputStream(Input input, CryptoCipher cipher, int bufferSize, Key key, AlgorithmParameterSpec params) throws IOException {
    this.input = input;
    this.cipher = cipher;
    this.bufferSize = checkBufferSize(cipher, bufferSize);
    this.key = key;
    this.params = params;
    if (!(params instanceof javax.crypto.spec.IvParameterSpec))
      throw new IOException("Illegal parameters"); 
    this.inBuffer = ByteBuffer.allocateDirect(this.bufferSize);
    this.outBuffer = ByteBuffer.allocateDirect(this.bufferSize + cipher
        .getBlockSize());
    this.outBuffer.limit(0);
    initCipher();
  }
  
  public int read() throws IOException {
    int n;
    while ((n = read(this.oneByteBuf, 0, 1)) == 0);
    return (n == -1) ? -1 : (this.oneByteBuf[0] & 0xFF);
  }
  
  public int read(byte[] array, int off, int len) throws IOException {
    checkStream();
    Objects.requireNonNull(array, "array");
    if (off < 0 || len < 0 || len > array.length - off)
      throw new IndexOutOfBoundsException(); 
    if (len == 0)
      return 0; 
    int remaining = this.outBuffer.remaining();
    if (remaining > 0) {
      int i = Math.min(len, remaining);
      this.outBuffer.get(array, off, i);
      return i;
    } 
    int nd = 0;
    while (nd == 0)
      nd = decryptMore(); 
    if (nd < 0)
      return nd; 
    int n = Math.min(len, this.outBuffer.remaining());
    this.outBuffer.get(array, off, n);
    return n;
  }
  
  public long skip(long n) throws IOException {
    Utils.checkArgument((n >= 0L), "Negative skip length.");
    checkStream();
    if (n == 0L)
      return 0L; 
    long remaining = n;
    while (remaining > 0L) {
      if (remaining <= this.outBuffer.remaining()) {
        int pos = this.outBuffer.position() + (int)remaining;
        this.outBuffer.position(pos);
        remaining = 0L;
        break;
      } 
      remaining -= this.outBuffer.remaining();
      this.outBuffer.clear();
      int nd = 0;
      while (nd == 0)
        nd = decryptMore(); 
      if (nd < 0)
        break; 
    } 
    return n - remaining;
  }
  
  public int available() throws IOException {
    checkStream();
    return this.input.available() + this.outBuffer.remaining();
  }
  
  public void close() throws IOException {
    if (this.closed)
      return; 
    this.input.close();
    freeBuffers();
    this.cipher.close();
    super.close();
    this.closed = true;
  }
  
  public boolean markSupported() {
    return false;
  }
  
  public boolean isOpen() {
    return !this.closed;
  }
  
  public int read(ByteBuffer dst) throws IOException {
    checkStream();
    int remaining = this.outBuffer.remaining();
    if (remaining <= 0) {
      int nd = 0;
      while (nd == 0)
        nd = decryptMore(); 
      if (nd < 0)
        return -1; 
    } 
    remaining = this.outBuffer.remaining();
    int toRead = dst.remaining();
    if (toRead <= remaining) {
      int limit = this.outBuffer.limit();
      this.outBuffer.limit(this.outBuffer.position() + toRead);
      dst.put(this.outBuffer);
      this.outBuffer.limit(limit);
      return toRead;
    } 
    dst.put(this.outBuffer);
    return remaining;
  }
  
  protected int getBufferSize() {
    return this.bufferSize;
  }
  
  protected Key getKey() {
    return this.key;
  }
  
  protected CryptoCipher getCipher() {
    return this.cipher;
  }
  
  protected AlgorithmParameterSpec getParams() {
    return this.params;
  }
  
  protected Input getInput() {
    return this.input;
  }
  
  protected void initCipher() throws IOException {
    try {
      this.cipher.init(2, this.key, this.params);
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
  }
  
  protected int decryptMore() throws IOException {
    if (this.finalDone)
      return -1; 
    int n = this.input.read(this.inBuffer);
    if (n < 0) {
      decryptFinal();
      int remaining = this.outBuffer.remaining();
      if (remaining > 0)
        return remaining; 
      return -1;
    } 
    if (n == 0)
      return 0; 
    decrypt();
    return this.outBuffer.remaining();
  }
  
  protected void decrypt() throws IOException {
    this.inBuffer.flip();
    this.outBuffer.clear();
    try {
      this.cipher.update(this.inBuffer, this.outBuffer);
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } 
    this.inBuffer.clear();
    this.outBuffer.flip();
  }
  
  protected void decryptFinal() throws IOException {
    this.inBuffer.flip();
    this.outBuffer.clear();
    try {
      this.cipher.doFinal(this.inBuffer, this.outBuffer);
      this.finalDone = true;
    } catch (ShortBufferException e) {
      throw new IOException(e);
    } catch (IllegalBlockSizeException e) {
      throw new IOException(e);
    } catch (BadPaddingException e) {
      throw new IOException(e);
    } 
    this.inBuffer.clear();
    this.outBuffer.flip();
  }
  
  protected void checkStream() throws IOException {
    if (this.closed)
      throw new IOException("Stream closed"); 
  }
  
  protected void freeBuffers() {
    freeDirectBuffer(this.inBuffer);
    freeDirectBuffer(this.outBuffer);
  }
  
  static void freeDirectBuffer(ByteBuffer buffer) {
    try {
      String SUN_CLASS = "sun.nio.ch.DirectBuffer";
      Class<?>[] interfaces = buffer.getClass().getInterfaces();
      for (Class<?> clazz : interfaces) {
        if (clazz.getName().equals("sun.nio.ch.DirectBuffer")) {
          Object[] NO_PARAM = new Object[0];
          Method getCleaner = Class.forName("sun.nio.ch.DirectBuffer").getMethod("cleaner", new Class[0]);
          Object cleaner = getCleaner.invoke(buffer, NO_PARAM);
          Method cleanMethod = Class.forName("sun.misc.Cleaner").getMethod("clean", new Class[0]);
          cleanMethod.invoke(cleaner, NO_PARAM);
          return;
        } 
      } 
    } catch (ReflectiveOperationException reflectiveOperationException) {}
  }
  
  static int getBufferSize(Properties props) {
    String bufferSizeStr = props.getProperty("commons.crypto.stream.buffer.size");
    if (bufferSizeStr == null || bufferSizeStr.isEmpty())
      return 8192; 
    return Integer.parseInt(bufferSizeStr);
  }
  
  static void checkStreamCipher(CryptoCipher cipher) throws IOException {
    if (!cipher.getAlgorithm().equals("AES/CTR/NoPadding"))
      throw new IOException("AES/CTR/NoPadding is required"); 
  }
  
  static int checkBufferSize(CryptoCipher cipher, int bufferSize) {
    Utils.checkArgument((bufferSize >= 512), "Minimum value of buffer size is 512.");
    return bufferSize - bufferSize % cipher
      .getBlockSize();
  }
}
