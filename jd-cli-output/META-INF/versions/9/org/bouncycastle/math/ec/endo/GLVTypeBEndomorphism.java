package META-INF.versions.9.org.bouncycastle.math.ec.endo;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPointMap;
import org.bouncycastle.math.ec.ScaleXPointMap;
import org.bouncycastle.math.ec.endo.EndoUtil;
import org.bouncycastle.math.ec.endo.GLVEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;

public class GLVTypeBEndomorphism implements GLVEndomorphism {
  protected final GLVTypeBParameters parameters;
  
  protected final ECPointMap pointMap;
  
  public GLVTypeBEndomorphism(ECCurve paramECCurve, GLVTypeBParameters paramGLVTypeBParameters) {
    this.parameters = paramGLVTypeBParameters;
    this.pointMap = new ScaleXPointMap(paramECCurve.fromBigInteger(paramGLVTypeBParameters.getBeta()));
  }
  
  public BigInteger[] decomposeScalar(BigInteger paramBigInteger) {
    return EndoUtil.decomposeScalar(this.parameters.getSplitParams(), paramBigInteger);
  }
  
  public ECPointMap getPointMap() {
    return this.pointMap;
  }
  
  public boolean hasEfficientPointMap() {
    return true;
  }
}
