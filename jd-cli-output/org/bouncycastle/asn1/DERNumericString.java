package org.bouncycastle.asn1;

public class DERNumericString extends ASN1NumericString {
  public static DERNumericString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERNumericString)
      return (DERNumericString)paramObject; 
    if (paramObject instanceof ASN1NumericString)
      return new DERNumericString(((ASN1NumericString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERNumericString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERNumericString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERNumericString) ? getInstance(aSN1Primitive) : new DERNumericString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERNumericString(String paramString) {
    this(paramString, false);
  }
  
  public DERNumericString(String paramString, boolean paramBoolean) {
    super(paramString, paramBoolean);
  }
  
  DERNumericString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
