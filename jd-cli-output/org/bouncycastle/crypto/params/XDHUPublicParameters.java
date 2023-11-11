package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class XDHUPublicParameters implements CipherParameters {
  private AsymmetricKeyParameter staticPublicKey;
  
  private AsymmetricKeyParameter ephemeralPublicKey;
  
  public XDHUPublicParameters(AsymmetricKeyParameter paramAsymmetricKeyParameter1, AsymmetricKeyParameter paramAsymmetricKeyParameter2) {
    if (paramAsymmetricKeyParameter1 == null)
      throw new NullPointerException("staticPublicKey cannot be null"); 
    if (!(paramAsymmetricKeyParameter1 instanceof X448PublicKeyParameters) && !(paramAsymmetricKeyParameter1 instanceof X25519PublicKeyParameters))
      throw new IllegalArgumentException("only X25519 and X448 paramaters can be used"); 
    if (paramAsymmetricKeyParameter2 == null)
      throw new NullPointerException("ephemeralPublicKey cannot be null"); 
    if (!paramAsymmetricKeyParameter1.getClass().isAssignableFrom(paramAsymmetricKeyParameter2.getClass()))
      throw new IllegalArgumentException("static and ephemeral public keys have different domain parameters"); 
    this.staticPublicKey = paramAsymmetricKeyParameter1;
    this.ephemeralPublicKey = paramAsymmetricKeyParameter2;
  }
  
  public AsymmetricKeyParameter getStaticPublicKey() {
    return this.staticPublicKey;
  }
  
  public AsymmetricKeyParameter getEphemeralPublicKey() {
    return this.ephemeralPublicKey;
  }
}
