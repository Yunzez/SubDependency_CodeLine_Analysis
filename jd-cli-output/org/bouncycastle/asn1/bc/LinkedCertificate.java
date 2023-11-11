package org.bouncycastle.asn1.bc;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

public class LinkedCertificate extends ASN1Object {
  private final DigestInfo digest;
  
  private final GeneralName certLocation;
  
  private X500Name certIssuer;
  
  private GeneralNames cACerts;
  
  public LinkedCertificate(DigestInfo paramDigestInfo, GeneralName paramGeneralName) {
    this(paramDigestInfo, paramGeneralName, null, null);
  }
  
  public LinkedCertificate(DigestInfo paramDigestInfo, GeneralName paramGeneralName, X500Name paramX500Name, GeneralNames paramGeneralNames) {
    this.digest = paramDigestInfo;
    this.certLocation = paramGeneralName;
    this.certIssuer = paramX500Name;
    this.cACerts = paramGeneralNames;
  }
  
  private LinkedCertificate(ASN1Sequence paramASN1Sequence) {
    this.digest = DigestInfo.getInstance(paramASN1Sequence.getObjectAt(0));
    this.certLocation = GeneralName.getInstance(paramASN1Sequence.getObjectAt(1));
    if (paramASN1Sequence.size() > 2)
      for (byte b = 2; b != paramASN1Sequence.size(); b++) {
        ASN1TaggedObject aSN1TaggedObject = ASN1TaggedObject.getInstance(paramASN1Sequence.getObjectAt(b));
        switch (aSN1TaggedObject.getTagNo()) {
          case 0:
            this.certIssuer = X500Name.getInstance(aSN1TaggedObject, false);
            break;
          case 1:
            this.cACerts = GeneralNames.getInstance(aSN1TaggedObject, false);
            break;
          default:
            throw new IllegalArgumentException("unknown tag in tagged field");
        } 
      }  
  }
  
  public static LinkedCertificate getInstance(Object paramObject) {
    return (paramObject instanceof LinkedCertificate) ? (LinkedCertificate)paramObject : ((paramObject != null) ? new LinkedCertificate(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public DigestInfo getDigest() {
    return this.digest;
  }
  
  public GeneralName getCertLocation() {
    return this.certLocation;
  }
  
  public X500Name getCertIssuer() {
    return this.certIssuer;
  }
  
  public GeneralNames getCACerts() {
    return this.cACerts;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(4);
    aSN1EncodableVector.add(this.digest);
    aSN1EncodableVector.add(this.certLocation);
    if (this.certIssuer != null)
      aSN1EncodableVector.add(new DERTaggedObject(false, 0, this.certIssuer)); 
    if (this.cACerts != null)
      aSN1EncodableVector.add(new DERTaggedObject(false, 1, this.cACerts)); 
    return new DERSequence(aSN1EncodableVector);
  }
}
