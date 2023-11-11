package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1VideotexString;

public class DERVideotexString extends ASN1VideotexString {
  public static org.bouncycastle.asn1.DERVideotexString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERVideotexString)
      return (org.bouncycastle.asn1.DERVideotexString)paramObject; 
    if (paramObject instanceof ASN1VideotexString)
      return new org.bouncycastle.asn1.DERVideotexString(((ASN1VideotexString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERVideotexString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERVideotexString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERVideotexString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERVideotexString(ASN1OctetString.getInstance(aSN1Primitive).getOctets());
  }
  
  public DERVideotexString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERVideotexString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
