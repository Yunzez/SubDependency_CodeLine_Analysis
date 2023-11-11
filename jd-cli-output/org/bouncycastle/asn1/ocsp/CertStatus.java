package org.bouncycastle.asn1.ocsp;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;

public class CertStatus extends ASN1Object implements ASN1Choice {
  private int tagNo;
  
  private ASN1Encodable value;
  
  public CertStatus() {
    this.tagNo = 0;
    this.value = DERNull.INSTANCE;
  }
  
  public CertStatus(RevokedInfo paramRevokedInfo) {
    this.tagNo = 1;
    this.value = paramRevokedInfo;
  }
  
  public CertStatus(int paramInt, ASN1Encodable paramASN1Encodable) {
    this.tagNo = paramInt;
    this.value = paramASN1Encodable;
  }
  
  private CertStatus(ASN1TaggedObject paramASN1TaggedObject) {
    int i = paramASN1TaggedObject.getTagNo();
    switch (i) {
      case 0:
        this.value = ASN1Null.getInstance(paramASN1TaggedObject, false);
        break;
      case 1:
        this.value = RevokedInfo.getInstance(paramASN1TaggedObject, false);
        break;
      case 2:
        this.value = ASN1Null.getInstance(paramASN1TaggedObject, false);
        break;
      default:
        throw new IllegalArgumentException("Unknown tag encountered: " + ASN1Util.getTagText(paramASN1TaggedObject));
    } 
    this.tagNo = i;
  }
  
  public static CertStatus getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof CertStatus)
      return (CertStatus)paramObject; 
    if (paramObject instanceof ASN1TaggedObject)
      return new CertStatus((ASN1TaggedObject)paramObject); 
    throw new IllegalArgumentException("unknown object in factory: " + paramObject.getClass().getName());
  }
  
  public static CertStatus getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return getInstance(paramASN1TaggedObject.getObject());
  }
  
  public int getTagNo() {
    return this.tagNo;
  }
  
  public ASN1Encodable getStatus() {
    return this.value;
  }
  
  public ASN1Primitive toASN1Primitive() {
    return new DERTaggedObject(false, this.tagNo, this.value);
  }
}
