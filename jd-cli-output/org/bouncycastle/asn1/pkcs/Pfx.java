package org.bouncycastle.asn1.pkcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;

public class Pfx extends ASN1Object implements PKCSObjectIdentifiers {
  private ContentInfo contentInfo;
  
  private MacData macData = null;
  
  private Pfx(ASN1Sequence paramASN1Sequence) {
    ASN1Integer aSN1Integer = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(0));
    if (!aSN1Integer.hasValue(3))
      throw new IllegalArgumentException("wrong version for PFX PDU"); 
    this.contentInfo = ContentInfo.getInstance(paramASN1Sequence.getObjectAt(1));
    if (paramASN1Sequence.size() == 3)
      this.macData = MacData.getInstance(paramASN1Sequence.getObjectAt(2)); 
  }
  
  public static Pfx getInstance(Object paramObject) {
    return (paramObject instanceof Pfx) ? (Pfx)paramObject : ((paramObject != null) ? new Pfx(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public Pfx(ContentInfo paramContentInfo, MacData paramMacData) {
    this.contentInfo = paramContentInfo;
    this.macData = paramMacData;
  }
  
  public ContentInfo getAuthSafe() {
    return this.contentInfo;
  }
  
  public MacData getMacData() {
    return this.macData;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
    aSN1EncodableVector.add(new ASN1Integer(3L));
    aSN1EncodableVector.add(this.contentInfo);
    if (this.macData != null)
      aSN1EncodableVector.add(this.macData); 
    return new BERSequence(aSN1EncodableVector);
  }
}
