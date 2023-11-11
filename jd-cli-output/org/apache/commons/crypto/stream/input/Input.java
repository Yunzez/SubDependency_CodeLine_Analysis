package org.apache.commons.crypto.stream.input;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;

public interface Input extends Closeable {
  int read(ByteBuffer paramByteBuffer) throws IOException;
  
  long skip(long paramLong) throws IOException;
  
  int available() throws IOException;
  
  int read(long paramLong, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IOException;
  
  void seek(long paramLong) throws IOException;
  
  void close() throws IOException;
}
