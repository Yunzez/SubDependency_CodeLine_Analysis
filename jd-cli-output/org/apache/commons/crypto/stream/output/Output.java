package org.apache.commons.crypto.stream.output;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;

public interface Output extends Closeable {
  int write(ByteBuffer paramByteBuffer) throws IOException;
  
  void flush() throws IOException;
  
  void close() throws IOException;
}
