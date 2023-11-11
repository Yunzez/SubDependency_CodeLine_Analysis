package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;

public class GOST3410ParameterSpec implements AlgorithmParameterSpec {
  private final ASN1ObjectIdentifier publicKeyParamSet;
  
  private final ASN1ObjectIdentifier digestParamSet;
  
  private final ASN1ObjectIdentifier encryptionParamSet;
  
  public GOST3410ParameterSpec(String paramString) {
    this(getOid(paramString), getDigestOid(paramString), null);
  }
  
  public GOST3410ParameterSpec(ASN1ObjectIdentifier paramASN1ObjectIdentifier1, ASN1ObjectIdentifier paramASN1ObjectIdentifier2) {
    this(paramASN1ObjectIdentifier1, paramASN1ObjectIdentifier2, null);
  }
  
  public GOST3410ParameterSpec(ASN1ObjectIdentifier paramASN1ObjectIdentifier1, ASN1ObjectIdentifier paramASN1ObjectIdentifier2, ASN1ObjectIdentifier paramASN1ObjectIdentifier3) {
    this.publicKeyParamSet = paramASN1ObjectIdentifier1;
    this.digestParamSet = paramASN1ObjectIdentifier2;
    this.encryptionParamSet = paramASN1ObjectIdentifier3;
  }
  
  public String getPublicKeyParamSetName() {
    return ECGOST3410NamedCurves.getName(getPublicKeyParamSet());
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
  
  private static ASN1ObjectIdentifier getOid(String paramString) {
    return ECGOST3410NamedCurves.getOID(paramString);
  }
  
  private static ASN1ObjectIdentifier getDigestOid(String paramString) {
    return (paramString.indexOf("12-512") > 0) ? RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512 : ((paramString.indexOf("12-256") > 0) ? RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256 : CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
  }
}
