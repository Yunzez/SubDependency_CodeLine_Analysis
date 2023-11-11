package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class DHMQVPrivateParameters implements CipherParameters {
  private DHPrivateKeyParameters staticPrivateKey;
  
  private DHPrivateKeyParameters ephemeralPrivateKey;
  
  private DHPublicKeyParameters ephemeralPublicKey;
  
  public DHMQVPrivateParameters(DHPrivateKeyParameters paramDHPrivateKeyParameters1, DHPrivateKeyParameters paramDHPrivateKeyParameters2) {
    this(paramDHPrivateKeyParameters1, paramDHPrivateKeyParameters2, null);
  }
  
  public DHMQVPrivateParameters(DHPrivateKeyParameters paramDHPrivateKeyParameters1, DHPrivateKeyParameters paramDHPrivateKeyParameters2, DHPublicKeyParameters paramDHPublicKeyParameters) {
    if (paramDHPrivateKeyParameters1 == null)
      throw new NullPointerException("staticPrivateKey cannot be null"); 
    if (paramDHPrivateKeyParameters2 == null)
      throw new NullPointerException("ephemeralPrivateKey cannot be null"); 
    DHParameters dHParameters = paramDHPrivateKeyParameters1.getParameters();
    if (!dHParameters.equals(paramDHPrivateKeyParameters2.getParameters()))
      throw new IllegalArgumentException("Static and ephemeral private keys have different domain parameters"); 
    if (paramDHPublicKeyParameters == null) {
      paramDHPublicKeyParameters = new DHPublicKeyParameters(dHParameters.getG().multiply(paramDHPrivateKeyParameters2.getX()), dHParameters);
    } else if (!dHParameters.equals(paramDHPublicKeyParameters.getParameters())) {
      throw new IllegalArgumentException("Ephemeral public key has different domain parameters");
    } 
    this.staticPrivateKey = paramDHPrivateKeyParameters1;
    this.ephemeralPrivateKey = paramDHPrivateKeyParameters2;
    this.ephemeralPublicKey = paramDHPublicKeyParameters;
  }
  
  public DHPrivateKeyParameters getStaticPrivateKey() {
    return this.staticPrivateKey;
  }
  
  public DHPrivateKeyParameters getEphemeralPrivateKey() {
    return this.ephemeralPrivateKey;
  }
  
  public DHPublicKeyParameters getEphemeralPublicKey() {
    return this.ephemeralPublicKey;
  }
}
