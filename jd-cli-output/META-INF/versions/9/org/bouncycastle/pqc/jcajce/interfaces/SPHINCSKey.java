package META-INF.versions.9.org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

public interface SPHINCSKey extends Key {
  byte[] getKeyData();
}
