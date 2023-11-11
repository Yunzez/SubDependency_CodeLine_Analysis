package org.bouncycastle.asn1;

public class DERGraphicString extends ASN1GraphicString {
  public static DERGraphicString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERGraphicString)
      return (DERGraphicString)paramObject; 
    if (paramObject instanceof ASN1GraphicString)
      return new DERGraphicString(((ASN1GraphicString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERGraphicString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERGraphicString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERGraphicString) ? getInstance(aSN1Primitive) : new DERGraphicString(ASN1OctetString.getInstance(aSN1Primitive).getOctets());
  }
  
  public DERGraphicString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERGraphicString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
