package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class CertificatePolicies extends ASN1Object {
  private final PolicyInformation[] policyInformation;
  
  private static PolicyInformation[] copy(PolicyInformation[] paramArrayOfPolicyInformation) {
    PolicyInformation[] arrayOfPolicyInformation = new PolicyInformation[paramArrayOfPolicyInformation.length];
    System.arraycopy(paramArrayOfPolicyInformation, 0, arrayOfPolicyInformation, 0, paramArrayOfPolicyInformation.length);
    return arrayOfPolicyInformation;
  }
  
  public static CertificatePolicies getInstance(Object paramObject) {
    return (paramObject instanceof CertificatePolicies) ? (CertificatePolicies)paramObject : ((paramObject != null) ? new CertificatePolicies(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public static CertificatePolicies getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return getInstance(ASN1Sequence.getInstance(paramASN1TaggedObject, paramBoolean));
  }
  
  public static CertificatePolicies fromExtensions(Extensions paramExtensions) {
    return getInstance(Extensions.getExtensionParsedValue(paramExtensions, Extension.certificatePolicies));
  }
  
  public CertificatePolicies(PolicyInformation paramPolicyInformation) {
    this.policyInformation = new PolicyInformation[] { paramPolicyInformation };
  }
  
  public CertificatePolicies(PolicyInformation[] paramArrayOfPolicyInformation) {
    this.policyInformation = copy(paramArrayOfPolicyInformation);
  }
  
  private CertificatePolicies(ASN1Sequence paramASN1Sequence) {
    this.policyInformation = new PolicyInformation[paramASN1Sequence.size()];
    for (byte b = 0; b != paramASN1Sequence.size(); b++)
      this.policyInformation[b] = PolicyInformation.getInstance(paramASN1Sequence.getObjectAt(b)); 
  }
  
  public PolicyInformation[] getPolicyInformation() {
    return copy(this.policyInformation);
  }
  
  public PolicyInformation getPolicyInformation(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    for (byte b = 0; b != this.policyInformation.length; b++) {
      if (paramASN1ObjectIdentifier.equals(this.policyInformation[b].getPolicyIdentifier()))
        return this.policyInformation[b]; 
    } 
    return null;
  }
  
  public ASN1Primitive toASN1Primitive() {
    return new DERSequence((ASN1Encodable[])this.policyInformation);
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    for (byte b = 0; b < this.policyInformation.length; b++) {
      if (stringBuffer.length() != 0)
        stringBuffer.append(", "); 
      stringBuffer.append(this.policyInformation[b]);
    } 
    return "CertificatePolicies: [" + stringBuffer + "]";
  }
}
