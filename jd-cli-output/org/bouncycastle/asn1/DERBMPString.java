package org.bouncycastle.asn1;

public class DERBMPString extends ASN1BMPString {
  public static DERBMPString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERBMPString)
      return (DERBMPString)paramObject; 
    if (paramObject instanceof ASN1BMPString)
      return new DERBMPString(((ASN1BMPString)paramObject).string); 
    if (paramObject instanceof byte[])
      try {
        return (DERBMPString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERBMPString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERBMPString) ? getInstance(aSN1Primitive) : new DERBMPString(ASN1OctetString.getInstance(aSN1Primitive).getOctets());
  }
  
  public DERBMPString(String paramString) {
    super(paramString);
  }
  
  DERBMPString(byte[] paramArrayOfbyte) {
    super(paramArrayOfbyte);
  }
  
  DERBMPString(char[] paramArrayOfchar) {
    super(paramArrayOfchar);
  }
}
