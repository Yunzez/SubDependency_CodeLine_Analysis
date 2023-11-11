package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERBMPString extends ASN1BMPString {
  public static org.bouncycastle.asn1.DERBMPString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERBMPString)
      return (org.bouncycastle.asn1.DERBMPString)paramObject; 
    if (paramObject instanceof ASN1BMPString)
      return new org.bouncycastle.asn1.DERBMPString(((ASN1BMPString)paramObject).string); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERBMPString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERBMPString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERBMPString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERBMPString(ASN1OctetString.getInstance(aSN1Primitive).getOctets());
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
