package org.bouncycastle.asn1.x509.qualified;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class BiometricData extends ASN1Object {
  private TypeOfBiometricData typeOfBiometricData;
  
  private AlgorithmIdentifier hashAlgorithm;
  
  private ASN1OctetString biometricDataHash;
  
  private ASN1IA5String sourceDataUri;
  
  public static BiometricData getInstance(Object paramObject) {
    return (paramObject instanceof BiometricData) ? (BiometricData)paramObject : ((paramObject != null) ? new BiometricData(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  private BiometricData(ASN1Sequence paramASN1Sequence) {
    Enumeration enumeration = paramASN1Sequence.getObjects();
    this.typeOfBiometricData = TypeOfBiometricData.getInstance(enumeration.nextElement());
    this.hashAlgorithm = AlgorithmIdentifier.getInstance(enumeration.nextElement());
    this.biometricDataHash = ASN1OctetString.getInstance(enumeration.nextElement());
    if (enumeration.hasMoreElements())
      this.sourceDataUri = ASN1IA5String.getInstance(enumeration.nextElement()); 
  }
  
  public BiometricData(TypeOfBiometricData paramTypeOfBiometricData, AlgorithmIdentifier paramAlgorithmIdentifier, ASN1OctetString paramASN1OctetString, ASN1IA5String paramASN1IA5String) {
    this.typeOfBiometricData = paramTypeOfBiometricData;
    this.hashAlgorithm = paramAlgorithmIdentifier;
    this.biometricDataHash = paramASN1OctetString;
    this.sourceDataUri = paramASN1IA5String;
  }
  
  public BiometricData(TypeOfBiometricData paramTypeOfBiometricData, AlgorithmIdentifier paramAlgorithmIdentifier, ASN1OctetString paramASN1OctetString) {
    this.typeOfBiometricData = paramTypeOfBiometricData;
    this.hashAlgorithm = paramAlgorithmIdentifier;
    this.biometricDataHash = paramASN1OctetString;
    this.sourceDataUri = null;
  }
  
  public TypeOfBiometricData getTypeOfBiometricData() {
    return this.typeOfBiometricData;
  }
  
  public AlgorithmIdentifier getHashAlgorithm() {
    return this.hashAlgorithm;
  }
  
  public ASN1OctetString getBiometricDataHash() {
    return this.biometricDataHash;
  }
  
  public DERIA5String getSourceDataUri() {
    return (null == this.sourceDataUri || this.sourceDataUri instanceof DERIA5String) ? (DERIA5String)this.sourceDataUri : new DERIA5String(this.sourceDataUri.getString(), false);
  }
  
  public ASN1IA5String getSourceDataUriIA5() {
    return this.sourceDataUri;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(4);
    aSN1EncodableVector.add(this.typeOfBiometricData);
    aSN1EncodableVector.add(this.hashAlgorithm);
    aSN1EncodableVector.add(this.biometricDataHash);
    if (this.sourceDataUri != null)
      aSN1EncodableVector.add(this.sourceDataUri); 
    return new DERSequence(aSN1EncodableVector);
  }
}
