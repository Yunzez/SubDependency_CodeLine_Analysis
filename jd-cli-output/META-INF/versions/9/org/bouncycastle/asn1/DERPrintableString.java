package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERPrintableString extends ASN1PrintableString {
  public static org.bouncycastle.asn1.DERPrintableString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERPrintableString)
      return (org.bouncycastle.asn1.DERPrintableString)paramObject; 
    if (paramObject instanceof ASN1PrintableString)
      return new org.bouncycastle.asn1.DERPrintableString(((ASN1PrintableString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERPrintableString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERPrintableString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERPrintableString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERPrintableString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
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
