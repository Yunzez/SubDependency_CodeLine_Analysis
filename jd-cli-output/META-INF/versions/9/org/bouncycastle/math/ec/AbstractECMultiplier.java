package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;

public abstract class AbstractECMultiplier implements ECMultiplier {
  public ECPoint multiply(ECPoint paramECPoint, BigInteger paramBigInteger) {
    int i = paramBigInteger.signum();
    if (i == 0 || paramECPoint.isInfinity())
      return paramECPoint.getCurve().getInfinity(); 
    ECPoint eCPoint1 = multiplyPositive(paramECPoint, paramBigInteger.abs());
    ECPoint eCPoint2 = (i > 0) ? eCPoint1 : eCPoint1.negate();
    return checkResult(eCPoint2);
  }
  
  protected abstract ECPoint multiplyPositive(ECPoint paramECPoint, BigInteger paramBigInteger);
  
  protected ECPoint checkResult(ECPoint paramECPoint) {
    return ECAlgorithms.implCheckResult(paramECPoint);
  }
}
