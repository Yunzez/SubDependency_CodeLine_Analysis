package org.bouncycastle.asn1.x509;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.util.Properties;

public class TBSCertificate extends ASN1Object {
  ASN1Sequence seq;
  
  ASN1Integer version;
  
  ASN1Integer serialNumber;
  
  AlgorithmIdentifier signature;
  
  X500Name issuer;
  
  Time startDate;
  
  Time endDate;
  
  X500Name subject;
  
  SubjectPublicKeyInfo subjectPublicKeyInfo;
  
  ASN1BitString issuerUniqueId;
  
  ASN1BitString subjectUniqueId;
  
  Extensions extensions;
  
  public static TBSCertificate getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return getInstance(ASN1Sequence.getInstance(paramASN1TaggedObject, paramBoolean));
  }
  
  public static TBSCertificate getInstance(Object paramObject) {
    return (paramObject instanceof TBSCertificate) ? (TBSCertificate)paramObject : ((paramObject != null) ? new TBSCertificate(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  private TBSCertificate(ASN1Sequence paramASN1Sequence) {
    byte b = 0;
    this.seq = paramASN1Sequence;
    if (paramASN1Sequence.getObjectAt(0) instanceof ASN1TaggedObject) {
      this.version = ASN1Integer.getInstance((ASN1TaggedObject)paramASN1Sequence.getObjectAt(0), true);
    } else {
      b = -1;
      this.version = new ASN1Integer(0L);
    } 
    boolean bool1 = false;
    boolean bool2 = false;
    if (this.version.hasValue(0)) {
      bool1 = true;
    } else if (this.version.hasValue(1)) {
      bool2 = true;
    } else if (!this.version.hasValue(2)) {
      throw new IllegalArgumentException("version number not recognised");
    } 
    this.serialNumber = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(b + 1));
    this.signature = AlgorithmIdentifier.getInstance(paramASN1Sequence.getObjectAt(b + 2));
    this.issuer = X500Name.getInstance(paramASN1Sequence.getObjectAt(b + 3));
    ASN1Sequence aSN1Sequence = (ASN1Sequence)paramASN1Sequence.getObjectAt(b + 4);
    this.startDate = Time.getInstance(aSN1Sequence.getObjectAt(0));
    this.endDate = Time.getInstance(aSN1Sequence.getObjectAt(1));
    this.subject = X500Name.getInstance(paramASN1Sequence.getObjectAt(b + 5));
    this.subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(paramASN1Sequence.getObjectAt(b + 6));
    int i = paramASN1Sequence.size() - b + 6 - 1;
    if (i != 0 && bool1)
      throw new IllegalArgumentException("version 1 certificate contains extra data"); 
    while (i > 0) {
      ASN1TaggedObject aSN1TaggedObject = (ASN1TaggedObject)paramASN1Sequence.getObjectAt(b + 6 + i);
      switch (aSN1TaggedObject.getTagNo()) {
        case 1:
          this.issuerUniqueId = DERBitString.getInstance(aSN1TaggedObject, false);
          break;
        case 2:
          this.subjectUniqueId = DERBitString.getInstance(aSN1TaggedObject, false);
          break;
        case 3:
          if (bool2)
            throw new IllegalArgumentException("version 2 certificate cannot contain extensions"); 
          this.extensions = Extensions.getInstance(ASN1Sequence.getInstance(aSN1TaggedObject, true));
          break;
        default:
          throw new IllegalArgumentException("Unknown tag encountered in structure: " + aSN1TaggedObject.getTagNo());
      } 
      i--;
    } 
  }
  
  public int getVersionNumber() {
    return this.version.intValueExact() + 1;
  }
  
  public ASN1Integer getVersion() {
    return this.version;
  }
  
  public ASN1Integer getSerialNumber() {
    return this.serialNumber;
  }
  
  public AlgorithmIdentifier getSignature() {
    return this.signature;
  }
  
  public X500Name getIssuer() {
    return this.issuer;
  }
  
  public Time getStartDate() {
    return this.startDate;
  }
  
  public Time getEndDate() {
    return this.endDate;
  }
  
  public X500Name getSubject() {
    return this.subject;
  }
  
  public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
    return this.subjectPublicKeyInfo;
  }
  
  public ASN1BitString getIssuerUniqueId() {
    return this.issuerUniqueId;
  }
  
  public ASN1BitString getSubjectUniqueId() {
    return this.subjectUniqueId;
  }
  
  public Extensions getExtensions() {
    return this.extensions;
  }
  
  public ASN1Primitive toASN1Primitive() {
    if (Properties.getPropertyValue("org.bouncycastle.x509.allow_non-der_tbscert") != null) {
      if (Properties.isOverrideSet("org.bouncycastle.x509.allow_non-der_tbscert"))
        return this.seq; 
    } else {
      return this.seq;
    } 
    ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector();
    if (!this.version.hasValue(0))
      aSN1EncodableVector1.add(new DERTaggedObject(true, 0, this.version)); 
    aSN1EncodableVector1.add(this.serialNumber);
    aSN1EncodableVector1.add(this.signature);
    aSN1EncodableVector1.add(this.issuer);
    ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector(2);
    aSN1EncodableVector2.add(this.startDate);
    aSN1EncodableVector2.add(this.endDate);
    aSN1EncodableVector1.add(new DERSequence(aSN1EncodableVector2));
    if (this.subject != null) {
      aSN1EncodableVector1.add(this.subject);
    } else {
      aSN1EncodableVector1.add(new DERSequence());
    } 
    aSN1EncodableVector1.add(this.subjectPublicKeyInfo);
    if (this.issuerUniqueId != null)
      aSN1EncodableVector1.add(new DERTaggedObject(false, 1, this.issuerUniqueId)); 
    if (this.subjectUniqueId != null)
      aSN1EncodableVector1.add(new DERTaggedObject(false, 2, this.subjectUniqueId)); 
    if (this.extensions != null)
      aSN1EncodableVector1.add(new DERTaggedObject(true, 3, this.extensions)); 
    return new DERSequence(aSN1EncodableVector1);
  }
}
