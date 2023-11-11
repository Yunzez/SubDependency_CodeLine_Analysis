package org.bouncycastle.math.ec.endo;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.PreCompInfo;

public class EndoPreCompInfo implements PreCompInfo {
  protected ECEndomorphism endomorphism;
  
  protected ECPoint mappedPoint;
  
  public ECEndomorphism getEndomorphism() {
    return this.endomorphism;
  }
  
  public void setEndomorphism(ECEndomorphism paramECEndomorphism) {
    this.endomorphism = paramECEndomorphism;
  }
  
  public ECPoint getMappedPoint() {
    return this.mappedPoint;
  }
  
  public void setMappedPoint(ECPoint paramECPoint) {
    this.mappedPoint = paramECPoint;
  }
}
