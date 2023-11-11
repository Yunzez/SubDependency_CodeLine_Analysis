package org.bouncycastle.asn1;

public class DERPrintableString extends ASN1PrintableString {
  public static DERPrintableString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof DERPrintableString)
      return (DERPrintableString)paramObject; 
    if (paramObject instanceof ASN1PrintableString)
      return new DERPrintableString(((ASN1PrintableString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (DERPrintableString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static DERPrintableString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    return (paramBoolean || aSN1Primitive instanceof DERPrintableString) ? getInstance(aSN1Primitive) : new DERPrintableString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERPrintableString(String paramString) {
    this(paramString, false);
  }
  
  public DERPrintableString(String paramString, boolean paramBoolean) {
    super(paramString, paramBoolean);
  }
  
  DERPrintableString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
