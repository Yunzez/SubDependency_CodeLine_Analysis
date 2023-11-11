package org.bouncycastle.math.ec.endo;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.PreCompCallback;
import org.bouncycastle.math.ec.PreCompInfo;

public abstract class EndoUtil {
  public static final String PRECOMP_NAME = "bc_endo";
  
  public static BigInteger[] decomposeScalar(ScalarSplitParameters paramScalarSplitParameters, BigInteger paramBigInteger) {
    int i = paramScalarSplitParameters.getBits();
    BigInteger bigInteger1 = calculateB(paramBigInteger, paramScalarSplitParameters.getG1(), i);
    BigInteger bigInteger2 = calculateB(paramBigInteger, paramScalarSplitParameters.getG2(), i);
    BigInteger bigInteger3 = paramBigInteger.subtract(bigInteger1.multiply(paramScalarSplitParameters.getV1A()).add(bigInteger2.multiply(paramScalarSplitParameters.getV2A())));
    BigInteger bigInteger4 = bigInteger1.multiply(paramScalarSplitParameters.getV1B()).add(bigInteger2.multiply(paramScalarSplitParameters.getV2B())).negate();
    return new BigInteger[] { bigInteger3, bigInteger4 };
  }
  
  public static ECPoint mapPoint(final ECEndomorphism endomorphism, final ECPoint p) {
    ECCurve eCCurve = p.getCurve();
    EndoPreCompInfo endoPreCompInfo = (EndoPreCompInfo)eCCurve.precompute(p, "bc_endo", new PreCompCallback() {
          public PreCompInfo precompute(PreCompInfo param1PreCompInfo) {
            EndoPreCompInfo endoPreCompInfo1 = (param1PreCompInfo instanceof EndoPreCompInfo) ? (EndoPreCompInfo)param1PreCompInfo : null;
            if (checkExisting(endoPreCompInfo1, endomorphism))
              return endoPreCompInfo1; 
            ECPoint eCPoint = endomorphism.getPointMap().map(p);
            EndoPreCompInfo endoPreCompInfo2 = new EndoPreCompInfo();
            endoPreCompInfo2.setEndomorphism(endomorphism);
            endoPreCompInfo2.setMappedPoint(eCPoint);
            return endoPreCompInfo2;
          }
          
          private boolean checkExisting(EndoPreCompInfo param1EndoPreCompInfo, ECEndomorphism param1ECEndomorphism) {
            return (null != param1EndoPreCompInfo && param1EndoPreCompInfo.getEndomorphism() == param1ECEndomorphism && param1EndoPreCompInfo.getMappedPoint() != null);
          }
        });
    return endoPreCompInfo.getMappedPoint();
  }
  
  private static BigInteger calculateB(BigInteger paramBigInteger1, BigInteger paramBigInteger2, int paramInt) {
    boolean bool = (paramBigInteger2.signum() < 0) ? true : false;
    BigInteger bigInteger = paramBigInteger1.multiply(paramBigInteger2.abs());
    boolean bool1 = bigInteger.testBit(paramInt - 1);
    bigInteger = bigInteger.shiftRight(paramInt);
    if (bool1)
      bigInteger = bigInteger.add(ECConstants.ONE); 
    return bool ? bigInteger.negate() : bigInteger;
  }
}
