package org.bouncycastle.asn1;

public class DERUTF8String extends ASN1UTF8String {
  public static DERUTF8String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERUTF8String)
      return (DERUTF8String)paramObject; 
    if (paramObject instanceof ASN1UTF8String)
      return new DERUTF8String(((ASN1UTF8String)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERUTF8String)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERUTF8String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERUTF8String) ? getInstance(aSN1Primitive) : new DERUTF8String(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERUTF8String(String paramString) {
    super(paramString);
  }
  
  DERUTF8String(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
