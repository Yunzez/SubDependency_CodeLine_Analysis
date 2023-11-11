package org.bouncycastle.crypto.params;

import org.bouncycastle.math.ec.ECPoint;

public class ECPublicKeyParameters extends ECKeyParameters {
  private final ECPoint q;
  
  public ECPublicKeyParameters(ECPoint paramECPoint, ECDomainParameters paramECDomainParameters) {
    super(false, paramECDomainParameters);
    this.q = paramECDomainParameters.validatePublicPoint(paramECPoint);
  }
  
  public ECPoint getQ() {
    return this.q;
  }
}
