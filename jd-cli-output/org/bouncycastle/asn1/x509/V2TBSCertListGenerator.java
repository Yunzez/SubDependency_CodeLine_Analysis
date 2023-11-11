package org.bouncycastle.asn1.x509;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;

public class V2TBSCertListGenerator {
  private ASN1Integer version = new ASN1Integer(1L);
  
  private AlgorithmIdentifier signature;
  
  private X500Name issuer;
  
  private Time thisUpdate;
  
  private Time nextUpdate = null;
  
  private Extensions extensions = null;
  
  private ASN1EncodableVector crlentries = new ASN1EncodableVector();
  
  private static final ASN1Sequence[] reasons = new ASN1Sequence[11];
  
  public void setSignature(AlgorithmIdentifier paramAlgorithmIdentifier) {
    this.signature = paramAlgorithmIdentifier;
  }
  
  public void setIssuer(X509Name paramX509Name) {
    this.issuer = X500Name.getInstance(paramX509Name.toASN1Primitive());
  }
  
  public void setIssuer(X500Name paramX500Name) {
    this.issuer = paramX500Name;
  }
  
  public void setThisUpdate(ASN1UTCTime paramASN1UTCTime) {
    this.thisUpdate = new Time(paramASN1UTCTime);
  }
  
  public void setNextUpdate(ASN1UTCTime paramASN1UTCTime) {
    this.nextUpdate = new Time(paramASN1UTCTime);
  }
  
  public void setThisUpdate(Time paramTime) {
    this.thisUpdate = paramTime;
  }
  
  public void setNextUpdate(Time paramTime) {
    this.nextUpdate = paramTime;
  }
  
  public void addCRLEntry(ASN1Sequence paramASN1Sequence) {
    this.crlentries.add(paramASN1Sequence);
  }
  
  public void addCRLEntry(ASN1Integer paramASN1Integer, ASN1UTCTime paramASN1UTCTime, int paramInt) {
    addCRLEntry(paramASN1Integer, new Time(paramASN1UTCTime), paramInt);
  }
  
  public void addCRLEntry(ASN1Integer paramASN1Integer, Time paramTime, int paramInt) {
    addCRLEntry(paramASN1Integer, paramTime, paramInt, null);
  }
  
  public void addCRLEntry(ASN1Integer paramASN1Integer, Time paramTime, int paramInt, ASN1GeneralizedTime paramASN1GeneralizedTime) {
    if (paramInt != 0) {
      ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
      if (paramInt < reasons.length) {
        if (paramInt < 0)
          throw new IllegalArgumentException("invalid reason value: " + paramInt); 
        aSN1EncodableVector.add(reasons[paramInt]);
      } else {
        aSN1EncodableVector.add(createReasonExtension(paramInt));
      } 
      if (paramASN1GeneralizedTime != null)
        aSN1EncodableVector.add(createInvalidityDateExtension(paramASN1GeneralizedTime)); 
      internalAddCRLEntry(paramASN1Integer, paramTime, new DERSequence(aSN1EncodableVector));
    } else if (paramASN1GeneralizedTime != null) {
      internalAddCRLEntry(paramASN1Integer, paramTime, new DERSequence(createInvalidityDateExtension(paramASN1GeneralizedTime)));
    } else {
      addCRLEntry(paramASN1Integer, paramTime, (Extensions)null);
    } 
  }
  
  private void internalAddCRLEntry(ASN1Integer paramASN1Integer, Time paramTime, ASN1Sequence paramASN1Sequence) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
    aSN1EncodableVector.add(paramASN1Integer);
    aSN1EncodableVector.add(paramTime);
    if (paramASN1Sequence != null)
      aSN1EncodableVector.add(paramASN1Sequence); 
    addCRLEntry(new DERSequence(aSN1EncodableVector));
  }
  
  public void addCRLEntry(ASN1Integer paramASN1Integer, Time paramTime, Extensions paramExtensions) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
    aSN1EncodableVector.add(paramASN1Integer);
    aSN1EncodableVector.add(paramTime);
    if (paramExtensions != null)
      aSN1EncodableVector.add(paramExtensions); 
    addCRLEntry(new DERSequence(aSN1EncodableVector));
  }
  
  public void setExtensions(X509Extensions paramX509Extensions) {
    setExtensions(Extensions.getInstance(paramX509Extensions));
  }
  
  public void setExtensions(Extensions paramExtensions) {
    this.extensions = paramExtensions;
  }
  
  public TBSCertList generateTBSCertList() {
    if (this.signature == null || this.issuer == null || this.thisUpdate == null)
      throw new IllegalStateException("Not all mandatory fields set in V2 TBSCertList generator."); 
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(7);
    aSN1EncodableVector.add(this.version);
    aSN1EncodableVector.add(this.signature);
    aSN1EncodableVector.add(this.issuer);
    aSN1EncodableVector.add(this.thisUpdate);
    if (this.nextUpdate != null)
      aSN1EncodableVector.add(this.nextUpdate); 
    if (this.crlentries.size() != 0)
      aSN1EncodableVector.add(new DERSequence(this.crlentries)); 
    if (this.extensions != null)
      aSN1EncodableVector.add(new DERTaggedObject(0, this.extensions)); 
    return new TBSCertList(new DERSequence(aSN1EncodableVector));
  }
  
  private static ASN1Sequence createReasonExtension(int paramInt) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    CRLReason cRLReason = CRLReason.lookup(paramInt);
    try {
      aSN1EncodableVector.add(Extension.reasonCode);
      aSN1EncodableVector.add(new DEROctetString(cRLReason.getEncoded()));
    } catch (IOException iOException) {
      throw new IllegalArgumentException("error encoding reason: " + iOException);
    } 
    return new DERSequence(aSN1EncodableVector);
  }
  
  private static ASN1Sequence createInvalidityDateExtension(ASN1GeneralizedTime paramASN1GeneralizedTime) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    try {
      aSN1EncodableVector.add(Extension.invalidityDate);
      aSN1EncodableVector.add(new DEROctetString(paramASN1GeneralizedTime.getEncoded()));
    } catch (IOException iOException) {
      throw new IllegalArgumentException("error encoding reason: " + iOException);
    } 
    return new DERSequence(aSN1EncodableVector);
  }
  
  static {
    reasons[0] = createReasonExtension(0);
    reasons[1] = createReasonExtension(1);
    reasons[2] = createReasonExtension(2);
    reasons[3] = createReasonExtension(3);
    reasons[4] = createReasonExtension(4);
    reasons[5] = createReasonExtension(5);
    reasons[6] = createReasonExtension(6);
    reasons[7] = createReasonExtension(7);
    reasons[8] = createReasonExtension(8);
    reasons[9] = createReasonExtension(9);
    reasons[10] = createReasonExtension(10);
  }
}
