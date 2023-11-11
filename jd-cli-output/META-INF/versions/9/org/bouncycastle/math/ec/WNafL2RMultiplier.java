package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.AbstractECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WNafPreCompInfo;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.Integers;

public class WNafL2RMultiplier extends AbstractECMultiplier {
  protected ECPoint multiplyPositive(ECPoint paramECPoint, BigInteger paramBigInteger) {
    int i = WNafUtil.getWindowSize(paramBigInteger.bitLength());
    WNafPreCompInfo wNafPreCompInfo = WNafUtil.precompute(paramECPoint, i, true);
    ECPoint[] arrayOfECPoint1 = wNafPreCompInfo.getPreComp();
    ECPoint[] arrayOfECPoint2 = wNafPreCompInfo.getPreCompNeg();
    int j = wNafPreCompInfo.getWidth();
    int[] arrayOfInt = WNafUtil.generateCompactWindowNaf(j, paramBigInteger);
    ECPoint eCPoint = paramECPoint.getCurve().getInfinity();
    int k = arrayOfInt.length;
    if (k > 1) {
      int m = arrayOfInt[--k];
      int n = m >> 16, i1 = m & 0xFFFF;
      int i2 = Math.abs(n);
      ECPoint[] arrayOfECPoint = (n < 0) ? arrayOfECPoint2 : arrayOfECPoint1;
      if (i2 << 2 < 1 << j) {
        int i3 = 32 - Integers.numberOfLeadingZeros(i2);
        int i4 = j - i3;
        int i5 = i2 ^ 1 << i3 - 1;
        int i6 = (1 << j - 1) - 1;
        int i7 = (i5 << i4) + 1;
        eCPoint = arrayOfECPoint[i6 >>> 1].add(arrayOfECPoint[i7 >>> 1]);
        i1 -= i4;
      } else {
        eCPoint = arrayOfECPoint[i2 >>> 1];
      } 
      eCPoint = eCPoint.timesPow2(i1);
    } 
    while (k > 0) {
      int m = arrayOfInt[--k];
      int n = m >> 16, i1 = m & 0xFFFF;
      int i2 = Math.abs(n);
      ECPoint[] arrayOfECPoint = (n < 0) ? arrayOfECPoint2 : arrayOfECPoint1;
      ECPoint eCPoint1 = arrayOfECPoint[i2 >>> 1];
      eCPoint = eCPoint.twicePlus(eCPoint1);
      eCPoint = eCPoint.timesPow2(i1);
    } 
    return eCPoint;
  }
}
