package org.apache.commons.crypto.utils;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import org.apache.commons.crypto.stream.input.Input;

public final class IoUtils {
  public static void readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
    int toRead = len;
    while (toRead > 0) {
      int ret = in.read(buf, off, toRead);
      if (ret < 0)
        throw new IOException("Premature EOF from inputStream"); 
      toRead -= ret;
      off += ret;
    } 
  }
  
  public static void readFully(Input in, long position, byte[] buffer, int offset, int length) throws IOException {
    int nread = 0;
    while (nread < length) {
      int nbytes = in.read(position + nread, buffer, offset + nread, length - nread);
      if (nbytes < 0)
        throw new IOException("End of stream reached before reading fully."); 
      nread += nbytes;
    } 
  }
  
  public static void cleanup(Closeable... closeables) {
    if (closeables != null)
      for (Closeable c : closeables)
        closeQuietly(c);  
  }
  
  public static void closeQuietly(Closeable closeable) {
    if (closeable != null)
      try {
        closeable.close();
      } catch (IOException iOException) {} 
  }
}
