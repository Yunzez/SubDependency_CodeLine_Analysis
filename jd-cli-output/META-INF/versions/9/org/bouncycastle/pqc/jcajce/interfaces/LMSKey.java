package META-INF.versions.9.org.bouncycastle.pqc.jcajce.interfaces;

import java.security.Key;

public interface LMSKey extends Key {
  int getLevels();
}
