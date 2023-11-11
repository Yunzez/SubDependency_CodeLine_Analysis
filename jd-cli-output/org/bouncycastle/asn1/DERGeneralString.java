package org.bouncycastle.asn1;

public class DERGeneralString extends ASN1GeneralString {
  public static DERGeneralString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERGeneralString)
      return (DERGeneralString)paramObject; 
    if (paramObject instanceof ASN1GeneralString)
      return new DERGeneralString(((ASN1GeneralString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERGeneralString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERGeneralString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERGeneralString) ? getInstance(aSN1Primitive) : new DERGeneralString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERGeneralString(String paramString) {
    super(paramString);
  }
  
  DERGeneralString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
