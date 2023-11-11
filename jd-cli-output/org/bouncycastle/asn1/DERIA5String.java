package org.bouncycastle.asn1;

public class DERIA5String extends ASN1IA5String {
  public static DERIA5String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERIA5String)
      return (DERIA5String)paramObject; 
    if (paramObject instanceof ASN1IA5String)
      return new DERIA5String(((ASN1IA5String)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERIA5String)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERIA5String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERIA5String) ? getInstance(aSN1Primitive) : new DERIA5String(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERIA5String(String paramString) {
    this(paramString, false);
  }
  
  public DERIA5String(String paramString, boolean paramBoolean) {
    super(paramString, paramBoolean);
  }
  
  DERIA5String(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
