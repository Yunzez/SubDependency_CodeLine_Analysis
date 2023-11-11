package org.bouncycastle.asn1;

public class DERVideotexString extends ASN1VideotexString {
  public static DERVideotexString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERVideotexString)
      return (DERVideotexString)paramObject; 
    if (paramObject instanceof ASN1VideotexString)
      return new DERVideotexString(((ASN1VideotexString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERVideotexString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERVideotexString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERVideotexString) ? getInstance(aSN1Primitive) : new DERVideotexString(ASN1OctetString.getInstance(aSN1Primitive).getOctets());
  }
  
  public DERVideotexString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERVideotexString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
