package META-INF.versions.9.org.bouncycastle.util;

import java.io.IOException;

public interface Encodable {
  byte[] getEncoded() throws IOException;
}
