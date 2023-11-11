package org.bouncycastle.asn1;

public class DERT61String extends ASN1T61String {
  public static DERT61String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERT61String)
      return (DERT61String)paramObject; 
    if (paramObject instanceof ASN1T61String)
      return new DERT61String(((ASN1T61String)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERT61String)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERT61String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERT61String) ? getInstance(aSN1Primitive) : new DERT61String(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERT61String(String paramString) {
    super(paramString);
  }
  
  public DERT61String(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERT61String(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
