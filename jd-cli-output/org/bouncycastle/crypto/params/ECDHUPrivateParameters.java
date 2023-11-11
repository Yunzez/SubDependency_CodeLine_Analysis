package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

public class ECDHUPrivateParameters implements CipherParameters {
  private ECPrivateKeyParameters staticPrivateKey;
  
  private ECPrivateKeyParameters ephemeralPrivateKey;
  
  private ECPublicKeyParameters ephemeralPublicKey;
  
  public ECDHUPrivateParameters(ECPrivateKeyParameters paramECPrivateKeyParameters1, ECPrivateKeyParameters paramECPrivateKeyParameters2) {
    this(paramECPrivateKeyParameters1, paramECPrivateKeyParameters2, null);
  }
  
  public ECDHUPrivateParameters(ECPrivateKeyParameters paramECPrivateKeyParameters1, ECPrivateKeyParameters paramECPrivateKeyParameters2, ECPublicKeyParameters paramECPublicKeyParameters) {
    if (paramECPrivateKeyParameters1 == null)
      throw new NullPointerException("staticPrivateKey cannot be null"); 
    if (paramECPrivateKeyParameters2 == null)
      throw new NullPointerException("ephemeralPrivateKey cannot be null"); 
    ECDomainParameters eCDomainParameters = paramECPrivateKeyParameters1.getParameters();
    if (!eCDomainParameters.equals(paramECPrivateKeyParameters2.getParameters()))
      throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters"); 
    if (paramECPublicKeyParameters == null) {
      ECPoint eCPoint = (new FixedPointCombMultiplier()).multiply(eCDomainParameters.getG(), paramECPrivateKeyParameters2.getD());
      paramECPublicKeyParameters = new ECPublicKeyParameters(eCPoint, eCDomainParameters);
    } else if (!eCDomainParameters.equals(paramECPublicKeyParameters.getParameters())) {
      throw new IllegalArgumentException("ephemeral public key has different domain parameters");
    } 
    this.staticPrivateKey = paramECPrivateKeyParameters1;
    this.ephemeralPrivateKey = paramECPrivateKeyParameters2;
    this.ephemeralPublicKey = paramECPublicKeyParameters;
  }
  
  public ECPrivateKeyParameters getStaticPrivateKey() {
    return this.staticPrivateKey;
  }
  
  public ECPrivateKeyParameters getEphemeralPrivateKey() {
    return this.ephemeralPrivateKey;
  }
  
  public ECPublicKeyParameters getEphemeralPublicKey() {
    return this.ephemeralPublicKey;
  }
}
