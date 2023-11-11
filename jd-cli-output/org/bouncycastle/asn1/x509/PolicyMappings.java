package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import java.util.Hashtable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class PolicyMappings extends ASN1Object {
  ASN1Sequence seq = null;
  
  public static PolicyMappings getInstance(Object paramObject) {
    return (paramObject instanceof PolicyMappings) ? (PolicyMappings)paramObject : ((paramObject != null) ? new PolicyMappings(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  private PolicyMappings(ASN1Sequence paramASN1Sequence) {
    this.seq = paramASN1Sequence;
  }
  
  public PolicyMappings(Hashtable paramHashtable) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(paramHashtable.size());
    Enumeration<String> enumeration = paramHashtable.keys();
    while (enumeration.hasMoreElements()) {
      String str1 = enumeration.nextElement();
      String str2 = (String)paramHashtable.get(str1);
      ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector(2);
      aSN1EncodableVector1.add(new ASN1ObjectIdentifier(str1));
      aSN1EncodableVector1.add(new ASN1ObjectIdentifier(str2));
      aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector1));
    } 
    this.seq = new DERSequence(aSN1EncodableVector);
  }
  
  public PolicyMappings(CertPolicyId paramCertPolicyId1, CertPolicyId paramCertPolicyId2) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    aSN1EncodableVector.add(paramCertPolicyId1);
    aSN1EncodableVector.add(paramCertPolicyId2);
    this.seq = new DERSequence(new DERSequence(aSN1EncodableVector));
  }
  
  public PolicyMappings(CertPolicyId[] paramArrayOfCertPolicyId1, CertPolicyId[] paramArrayOfCertPolicyId2) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(paramArrayOfCertPolicyId1.length);
    for (byte b = 0; b != paramArrayOfCertPolicyId1.length; b++) {
      ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector(2);
      aSN1EncodableVector1.add(paramArrayOfCertPolicyId1[b]);
      aSN1EncodableVector1.add(paramArrayOfCertPolicyId2[b]);
      aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector1));
    } 
    this.seq = new DERSequence(aSN1EncodableVector);
  }
  
  public ASN1Primitive toASN1Primitive() {
    return this.seq;
  }
}
