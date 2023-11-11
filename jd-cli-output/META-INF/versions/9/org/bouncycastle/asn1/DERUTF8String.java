package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UTF8String;

public class DERUTF8String extends ASN1UTF8String {
  public static org.bouncycastle.asn1.DERUTF8String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERUTF8String)
      return (org.bouncycastle.asn1.DERUTF8String)paramObject; 
    if (paramObject instanceof ASN1UTF8String)
      return new org.bouncycastle.asn1.DERUTF8String(((ASN1UTF8String)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERUTF8String)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject
        .getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERUTF8String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERUTF8String)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERUTF8String(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERUTF8String(String paramString) {
    super(paramString);
  }
  
  DERUTF8String(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
