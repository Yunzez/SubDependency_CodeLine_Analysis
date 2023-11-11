package org.bouncycastle.jcajce.spec;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Arrays;

public class DHUParameterSpec implements AlgorithmParameterSpec {
  private final PublicKey ephemeralPublicKey;
  
  private final PrivateKey ephemeralPrivateKey;
  
  private final PublicKey otherPartyEphemeralKey;
  
  private final byte[] userKeyingMaterial;
  
  public DHUParameterSpec(PublicKey paramPublicKey1, PrivateKey paramPrivateKey, PublicKey paramPublicKey2, byte[] paramArrayOfbyte) {
    if (paramPrivateKey == null)
      throw new IllegalArgumentException("ephemeral private key cannot be null"); 
    if (paramPublicKey2 == null)
      throw new IllegalArgumentException("other party ephemeral key cannot be null"); 
    this.ephemeralPublicKey = paramPublicKey1;
    this.ephemeralPrivateKey = paramPrivateKey;
    this.otherPartyEphemeralKey = paramPublicKey2;
    this.userKeyingMaterial = Arrays.clone(paramArrayOfbyte);
  }
  
  public DHUParameterSpec(PublicKey paramPublicKey1, PrivateKey paramPrivateKey, PublicKey paramPublicKey2) {
    this(paramPublicKey1, paramPrivateKey, paramPublicKey2, null);
  }
  
  public DHUParameterSpec(KeyPair paramKeyPair, PublicKey paramPublicKey, byte[] paramArrayOfbyte) {
    this(paramKeyPair.getPublic(), paramKeyPair.getPrivate(), paramPublicKey, paramArrayOfbyte);
  }
  
  public DHUParameterSpec(PrivateKey paramPrivateKey, PublicKey paramPublicKey, byte[] paramArrayOfbyte) {
    this(null, paramPrivateKey, paramPublicKey, paramArrayOfbyte);
  }
  
  public DHUParameterSpec(KeyPair paramKeyPair, PublicKey paramPublicKey) {
    this(paramKeyPair.getPublic(), paramKeyPair.getPrivate(), paramPublicKey, null);
  }
  
  public DHUParameterSpec(PrivateKey paramPrivateKey, PublicKey paramPublicKey) {
    this(null, paramPrivateKey, paramPublicKey, null);
  }
  
  public PrivateKey getEphemeralPrivateKey() {
    return this.ephemeralPrivateKey;
  }
  
  public PublicKey getEphemeralPublicKey() {
    return this.ephemeralPublicKey;
  }
  
  public PublicKey getOtherPartyEphemeralKey() {
    return this.otherPartyEphemeralKey;
  }
  
  public byte[] getUserKeyingMaterial() {
    return Arrays.clone(this.userKeyingMaterial);
  }
}
