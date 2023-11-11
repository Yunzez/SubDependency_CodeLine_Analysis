package org.bouncycastle.math.ec;

public class ScaleYNegateXPointMap implements ECPointMap {
  protected final ECFieldElement scale;
  
  public ScaleYNegateXPointMap(ECFieldElement paramECFieldElement) {
    this.scale = paramECFieldElement;
  }
  
  public ECPoint map(ECPoint paramECPoint) {
    return paramECPoint.scaleYNegateX(this.scale);
  }
}
