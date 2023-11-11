package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

public interface ECMultiplier {
  ECPoint multiply(ECPoint paramECPoint, BigInteger paramBigInteger);
}
