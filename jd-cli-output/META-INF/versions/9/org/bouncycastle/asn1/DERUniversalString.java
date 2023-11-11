package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalString;

public class DERUniversalString extends ASN1UniversalString {
  public static org.bouncycastle.asn1.DERUniversalString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERUniversalString)
      return (org.bouncycastle.asn1.DERUniversalString)paramObject; 
    if (paramObject instanceof ASN1UniversalString)
      return new org.bouncycastle.asn1.DERUniversalString(((ASN1UniversalString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERUniversalString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERUniversalString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERUniversalString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERUniversalString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERUniversalString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERUniversalString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
