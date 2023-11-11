package org.bouncycastle.math.ec;

public class ScaleXNegateYPointMap implements ECPointMap {
  protected final ECFieldElement scale;
  
  public ScaleXNegateYPointMap(ECFieldElement paramECFieldElement) {
    this.scale = paramECFieldElement;
  }
  
  public ECPoint map(ECPoint paramECPoint) {
    return paramECPoint.scaleXNegateY(this.scale);
  }
}
