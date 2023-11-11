package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1VisibleString;

public class DERVisibleString extends ASN1VisibleString {
  public static org.bouncycastle.asn1.DERVisibleString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERVisibleString)
      return (org.bouncycastle.asn1.DERVisibleString)paramObject; 
    if (paramObject instanceof ASN1VisibleString)
      return new org.bouncycastle.asn1.DERVisibleString(((ASN1VisibleString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERVisibleString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERVisibleString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERVisibleString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERVisibleString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERVisibleString(String paramString) {
    super(paramString);
  }
  
  DERVisibleString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
