package META-INF.versions.9.org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;
import org.bouncycastle.pqc.jcajce.interfaces.NHKey;

public interface NHPrivateKey extends NHKey, PrivateKey {
  short[] getSecretData();
}
