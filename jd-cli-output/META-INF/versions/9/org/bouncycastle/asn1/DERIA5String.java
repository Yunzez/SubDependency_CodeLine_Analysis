package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERIA5String extends ASN1IA5String {
  public static org.bouncycastle.asn1.DERIA5String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERIA5String)
      return (org.bouncycastle.asn1.DERIA5String)paramObject; 
    if (paramObject instanceof ASN1IA5String)
      return new org.bouncycastle.asn1.DERIA5String(((ASN1IA5String)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERIA5String)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERIA5String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERIA5String)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERIA5String(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
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
