package org.bouncycastle.math.ec;

import java.math.BigInteger;

public class FixedPointUtil {
  public static final String PRECOMP_NAME = "bc_fixed_point";
  
  public static int getCombSize(ECCurve paramECCurve) {
    BigInteger bigInteger = paramECCurve.getOrder();
    return (bigInteger == null) ? (paramECCurve.getFieldSize() + 1) : bigInteger.bitLength();
  }
  
  public static FixedPointPreCompInfo getFixedPointPreCompInfo(PreCompInfo paramPreCompInfo) {
    return (paramPreCompInfo instanceof FixedPointPreCompInfo) ? (FixedPointPreCompInfo)paramPreCompInfo : null;
  }
  
  public static FixedPointPreCompInfo precompute(final ECPoint p) {
    final ECCurve c = p.getCurve();
    return (FixedPointPreCompInfo)eCCurve.precompute(p, "bc_fixed_point", new PreCompCallback() {
          public PreCompInfo precompute(PreCompInfo param1PreCompInfo) {
            FixedPointPreCompInfo fixedPointPreCompInfo1 = (param1PreCompInfo instanceof FixedPointPreCompInfo) ? (FixedPointPreCompInfo)param1PreCompInfo : null;
            int i = FixedPointUtil.getCombSize(c);
            byte b1 = (i > 250) ? 6 : 5;
            int j = 1 << b1;
            if (checkExisting(fixedPointPreCompInfo1, j))
              return fixedPointPreCompInfo1; 
            int k = (i + b1 - 1) / b1;
            ECPoint[] arrayOfECPoint1 = new ECPoint[b1 + 1];
            arrayOfECPoint1[0] = p;
            for (byte b2 = 1; b2 < b1; b2++)
              arrayOfECPoint1[b2] = arrayOfECPoint1[b2 - 1].timesPow2(k); 
            arrayOfECPoint1[b1] = arrayOfECPoint1[0].subtract(arrayOfECPoint1[1]);
            c.normalizeAll(arrayOfECPoint1);
            ECPoint[] arrayOfECPoint2 = new ECPoint[j];
            arrayOfECPoint2[0] = arrayOfECPoint1[0];
            for (int m = b1 - 1; m >= 0; m--) {
              ECPoint eCPoint = arrayOfECPoint1[m];
              int n = 1 << m;
              int i1;
              for (i1 = n; i1 < j; i1 += n << 1)
                arrayOfECPoint2[i1] = arrayOfECPoint2[i1 - n].add(eCPoint); 
            } 
            c.normalizeAll(arrayOfECPoint2);
            FixedPointPreCompInfo fixedPointPreCompInfo2 = new FixedPointPreCompInfo();
            fixedPointPreCompInfo2.setLookupTable(c.createCacheSafeLookupTable(arrayOfECPoint2, 0, arrayOfECPoint2.length));
            fixedPointPreCompInfo2.setOffset(arrayOfECPoint1[b1]);
            fixedPointPreCompInfo2.setWidth(b1);
            return fixedPointPreCompInfo2;
          }
          
          private boolean checkExisting(FixedPointPreCompInfo param1FixedPointPreCompInfo, int param1Int) {
            return (param1FixedPointPreCompInfo != null && checkTable(param1FixedPointPreCompInfo.getLookupTable(), param1Int));
          }
          
          private boolean checkTable(ECLookupTable param1ECLookupTable, int param1Int) {
            return (param1ECLookupTable != null && param1ECLookupTable.getSize() >= param1Int);
          }
        });
  }
}
