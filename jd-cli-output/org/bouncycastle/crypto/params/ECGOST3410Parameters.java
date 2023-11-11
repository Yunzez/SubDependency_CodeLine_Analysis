package org.bouncycastle.crypto.params;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public class ECGOST3410Parameters extends ECNamedDomainParameters {
  private final ASN1ObjectIdentifier publicKeyParamSet;
  
  private final ASN1ObjectIdentifier digestParamSet;
  
  private final ASN1ObjectIdentifier encryptionParamSet;
  
  public ECGOST3410Parameters(ECDomainParameters paramECDomainParameters, ASN1ObjectIdentifier paramASN1ObjectIdentifier1, ASN1ObjectIdentifier paramASN1ObjectIdentifier2) {
    this(paramECDomainParameters, paramASN1ObjectIdentifier1, paramASN1ObjectIdentifier2, null);
  }
  
  public ECGOST3410Parameters(ECDomainParameters paramECDomainParameters, ASN1ObjectIdentifier paramASN1ObjectIdentifier1, ASN1ObjectIdentifier paramASN1ObjectIdentifier2, ASN1ObjectIdentifier paramASN1ObjectIdentifier3) {
    super(paramASN1ObjectIdentifier1, paramECDomainParameters);
    if (paramECDomainParameters instanceof ECNamedDomainParameters && !paramASN1ObjectIdentifier1.equals(((ECNamedDomainParameters)paramECDomainParameters).getName()))
      throw new IllegalArgumentException("named parameters do not match publicKeyParamSet value"); 
    this.publicKeyParamSet = paramASN1ObjectIdentifier1;
    this.digestParamSet = paramASN1ObjectIdentifier2;
    this.encryptionParamSet = paramASN1ObjectIdentifier3;
  }
  
  public ASN1ObjectIdentifier getPublicKeyParamSet() {
    return this.publicKeyParamSet;
  }
  
  public ASN1ObjectIdentifier getDigestParamSet() {
    return this.digestParamSet;
  }
  
  public ASN1ObjectIdentifier getEncryptionParamSet() {
    return this.encryptionParamSet;
  }
}
