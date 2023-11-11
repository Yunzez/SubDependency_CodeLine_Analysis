package org.apache.commons.crypto.stream.output;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class StreamOutput implements Output {
  private final byte[] buf;
  
  private final int bufferSize;
  
  private final OutputStream out;
  
  public StreamOutput(OutputStream out, int bufferSize) {
    this.out = out;
    this.bufferSize = bufferSize;
    this.buf = new byte[bufferSize];
  }
  
  public int write(ByteBuffer src) throws IOException {
    int len = src.remaining();
    int remaining = len;
    while (remaining > 0) {
      int n = Math.min(remaining, this.bufferSize);
      src.get(this.buf, 0, n);
      this.out.write(this.buf, 0, n);
      remaining = src.remaining();
    } 
    return len;
  }
  
  public void flush() throws IOException {
    this.out.flush();
  }
  
  public void close() throws IOException {
    this.out.close();
  }
  
  protected OutputStream getOut() {
    return this.out;
  }
}
