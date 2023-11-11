package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.LimitedInputStream;

class StreamUtil {
  private static final long MAX_MEMORY = Runtime.getRuntime().maxMemory();
  
  static int findLimit(InputStream paramInputStream) {
    if (paramInputStream instanceof LimitedInputStream)
      return ((LimitedInputStream)paramInputStream).getLimit(); 
    if (paramInputStream instanceof ASN1InputStream)
      return ((ASN1InputStream)paramInputStream).getLimit(); 
    if (paramInputStream instanceof ByteArrayInputStream)
      return ((ByteArrayInputStream)paramInputStream).available(); 
    if (paramInputStream instanceof FileInputStream)
      try {
        FileChannel fileChannel = ((FileInputStream)paramInputStream).getChannel();
        long l = (fileChannel != null) ? fileChannel.size() : 2147483647L;
        if (l < 2147483647L)
          return (int)l; 
      } catch (IOException iOException) {} 
    if (MAX_MEMORY > 2147483647L)
      return Integer.MAX_VALUE; 
    return (int)MAX_MEMORY;
  }
}
