package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1GeneralString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERGeneralString extends ASN1GeneralString {
  public static org.bouncycastle.asn1.DERGeneralString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERGeneralString)
      return (org.bouncycastle.asn1.DERGeneralString)paramObject; 
    if (paramObject instanceof ASN1GeneralString)
      return new org.bouncycastle.asn1.DERGeneralString(((ASN1GeneralString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERGeneralString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject
        .getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERGeneralString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERGeneralString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERGeneralString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERGeneralString(String paramString) {
    super(paramString);
  }
  
  DERGeneralString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
