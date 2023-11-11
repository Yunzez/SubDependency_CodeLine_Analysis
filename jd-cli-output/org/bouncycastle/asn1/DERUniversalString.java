package org.bouncycastle.asn1;

public class DERUniversalString extends ASN1UniversalString {
  public static DERUniversalString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERUniversalString)
      return (DERUniversalString)paramObject; 
    if (paramObject instanceof ASN1UniversalString)
      return new DERUniversalString(((ASN1UniversalString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERUniversalString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERUniversalString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERUniversalString) ? getInstance(aSN1Primitive) : new DERUniversalString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERUniversalString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERUniversalString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
