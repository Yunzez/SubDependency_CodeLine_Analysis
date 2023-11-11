package META-INF.versions.9.org.bouncycastle.jce.interfaces;

import java.math.BigInteger;
import java.security.PrivateKey;
import org.bouncycastle.jce.interfaces.ECKey;

public interface ECPrivateKey extends ECKey, PrivateKey {
  BigInteger getD();
}
