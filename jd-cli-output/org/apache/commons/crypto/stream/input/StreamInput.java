package org.apache.commons.crypto.stream.input;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

public class StreamInput implements Input {
  private final byte[] buf;
  
  private final int bufferSize;
  
  final InputStream in;
  
  public StreamInput(InputStream inputStream, int bufferSize) {
    this.in = inputStream;
    this.bufferSize = bufferSize;
    this.buf = new byte[bufferSize];
  }
  
  public int read(ByteBuffer dst) throws IOException {
    int remaining = dst.remaining();
    int read = 0;
    while (remaining > 0) {
      int n = this.in.read(this.buf, 0, Math.min(remaining, this.bufferSize));
      if (n == -1) {
        if (read == 0)
          read = -1; 
        break;
      } 
      if (n > 0) {
        dst.put(this.buf, 0, n);
        read += n;
        remaining -= n;
      } 
    } 
    return read;
  }
  
  public long skip(long n) throws IOException {
    return this.in.skip(n);
  }
  
  public int available() throws IOException {
    return this.in.available();
  }
  
  public int read(long position, byte[] buffer, int offset, int length) throws IOException {
    throw new UnsupportedOperationException("Positioned read is not supported by this implementation");
  }
  
  public void seek(long position) throws IOException {
    throw new UnsupportedOperationException("Seek is not supported by this implementation");
  }
  
  public void close() throws IOException {
    this.in.close();
  }
}
