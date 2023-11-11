package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

public class XDHUPrivateParameters implements CipherParameters {
  private AsymmetricKeyParameter staticPrivateKey;
  
  private AsymmetricKeyParameter ephemeralPrivateKey;
  
  private AsymmetricKeyParameter ephemeralPublicKey;
  
  public XDHUPrivateParameters(AsymmetricKeyParameter paramAsymmetricKeyParameter1, AsymmetricKeyParameter paramAsymmetricKeyParameter2) {
    this(paramAsymmetricKeyParameter1, paramAsymmetricKeyParameter2, null);
  }
  
  public XDHUPrivateParameters(AsymmetricKeyParameter paramAsymmetricKeyParameter1, AsymmetricKeyParameter paramAsymmetricKeyParameter2, AsymmetricKeyParameter paramAsymmetricKeyParameter3) {
    if (paramAsymmetricKeyParameter1 == null)
      throw new NullPointerException("staticPrivateKey cannot be null"); 
    if (!(paramAsymmetricKeyParameter1 instanceof X448PrivateKeyParameters) && !(paramAsymmetricKeyParameter1 instanceof X25519PrivateKeyParameters))
      throw new IllegalArgumentException("only X25519 and X448 paramaters can be used"); 
    if (paramAsymmetricKeyParameter2 == null)
      throw new NullPointerException("ephemeralPrivateKey cannot be null"); 
    if (!paramAsymmetricKeyParameter1.getClass().isAssignableFrom(paramAsymmetricKeyParameter2.getClass()))
      throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters"); 
    if (paramAsymmetricKeyParameter3 == null) {
      if (paramAsymmetricKeyParameter2 instanceof X448PrivateKeyParameters) {
        paramAsymmetricKeyParameter3 = ((X448PrivateKeyParameters)paramAsymmetricKeyParameter2).generatePublicKey();
      } else {
        paramAsymmetricKeyParameter3 = ((X25519PrivateKeyParameters)paramAsymmetricKeyParameter2).generatePublicKey();
      } 
    } else {
      if (paramAsymmetricKeyParameter3 instanceof X448PublicKeyParameters && !(paramAsymmetricKeyParameter1 instanceof X448PrivateKeyParameters))
        throw new IllegalArgumentException("ephemeral public key has different domain parameters"); 
      if (paramAsymmetricKeyParameter3 instanceof X25519PublicKeyParameters && !(paramAsymmetricKeyParameter1 instanceof X25519PrivateKeyParameters))
        throw new IllegalArgumentException("ephemeral public key has different domain parameters"); 
    } 
    this.staticPrivateKey = paramAsymmetricKeyParameter1;
    this.ephemeralPrivateKey = paramAsymmetricKeyParameter2;
    this.ephemeralPublicKey = paramAsymmetricKeyParameter3;
  }
  
  public AsymmetricKeyParameter getStaticPrivateKey() {
    return this.staticPrivateKey;
  }
  
  public AsymmetricKeyParameter getEphemeralPrivateKey() {
    return this.ephemeralPrivateKey;
  }
  
  public AsymmetricKeyParameter getEphemeralPublicKey() {
    return this.ephemeralPublicKey;
  }
}
