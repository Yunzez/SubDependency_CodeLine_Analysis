package org.bouncycastle.asn1;

public class DERVisibleString extends ASN1VisibleString {
  public static DERVisibleString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERVisibleString)
      return (DERVisibleString)paramObject; 
    if (paramObject instanceof ASN1VisibleString)
      return new DERVisibleString(((ASN1VisibleString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERVisibleString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERVisibleString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERVisibleString) ? getInstance(aSN1Primitive) : new DERVisibleString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERVisibleString(String paramString) {
    super(paramString);
  }
  
  DERVisibleString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
