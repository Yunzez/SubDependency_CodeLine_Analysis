package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class SM2KeyExchangePublicParameters implements CipherParameters {
  private final ECPublicKeyParameters staticPublicKey;
  
  private final ECPublicKeyParameters ephemeralPublicKey;
  
  public SM2KeyExchangePublicParameters(ECPublicKeyParameters paramECPublicKeyParameters1, ECPublicKeyParameters paramECPublicKeyParameters2) {
    if (paramECPublicKeyParameters1 == null)
      throw new NullPointerException("staticPublicKey cannot be null"); 
    if (paramECPublicKeyParameters2 == null)
      throw new NullPointerException("ephemeralPublicKey cannot be null"); 
    if (!paramECPublicKeyParameters1.getParameters().equals(paramECPublicKeyParameters2.getParameters()))
      throw new IllegalArgumentException("Static and ephemeral public keys have different domain parameters"); 
    this.staticPublicKey = paramECPublicKeyParameters1;
    this.ephemeralPublicKey = paramECPublicKeyParameters2;
  }
  
  public ECPublicKeyParameters getStaticPublicKey() {
    return this.staticPublicKey;
  }
  
  public ECPublicKeyParameters getEphemeralPublicKey() {
    return this.ephemeralPublicKey;
  }
}
