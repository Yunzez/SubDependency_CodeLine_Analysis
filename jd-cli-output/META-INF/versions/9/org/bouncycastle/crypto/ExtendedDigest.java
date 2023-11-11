package META-INF.versions.9.org.bouncycastle.crypto;

import org.bouncycastle.crypto.Digest;

public interface ExtendedDigest extends Digest {
  int getByteLength();
}
