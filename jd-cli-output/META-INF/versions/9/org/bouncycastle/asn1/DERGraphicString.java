package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1GraphicString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERGraphicString extends ASN1GraphicString {
  public static org.bouncycastle.asn1.DERGraphicString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERGraphicString)
      return (org.bouncycastle.asn1.DERGraphicString)paramObject; 
    if (paramObject instanceof ASN1GraphicString)
      return new org.bouncycastle.asn1.DERGraphicString(((ASN1GraphicString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERGraphicString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERGraphicString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERGraphicString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERGraphicString(ASN1OctetString.getInstance(aSN1Primitive).getOctets());
  }
  
  public DERGraphicString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERGraphicString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
