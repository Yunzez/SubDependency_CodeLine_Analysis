package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointPreCompInfo;
import org.bouncycastle.math.ec.PreCompCallback;
import org.bouncycastle.math.ec.PreCompInfo;

public class FixedPointUtil {
  public static final String PRECOMP_NAME = "bc_fixed_point";
  
  public static int getCombSize(ECCurve paramECCurve) {
    BigInteger bigInteger = paramECCurve.getOrder();
    return (bigInteger == null) ? (paramECCurve.getFieldSize() + 1) : bigInteger.bitLength();
  }
  
  public static FixedPointPreCompInfo getFixedPointPreCompInfo(PreCompInfo paramPreCompInfo) {
    return (paramPreCompInfo instanceof FixedPointPreCompInfo) ? (FixedPointPreCompInfo)paramPreCompInfo : null;
  }
  
  public static FixedPointPreCompInfo precompute(ECPoint paramECPoint) {
    ECCurve eCCurve = paramECPoint.getCurve();
    return (FixedPointPreCompInfo)eCCurve.precompute(paramECPoint, "bc_fixed_point", (PreCompCallback)new Object(eCCurve, paramECPoint));
  }
}
