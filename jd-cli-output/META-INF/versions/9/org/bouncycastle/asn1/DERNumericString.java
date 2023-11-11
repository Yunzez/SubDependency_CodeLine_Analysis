package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1NumericString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERNumericString extends ASN1NumericString {
  public static org.bouncycastle.asn1.DERNumericString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERNumericString)
      return (org.bouncycastle.asn1.DERNumericString)paramObject; 
    if (paramObject instanceof ASN1NumericString)
      return new org.bouncycastle.asn1.DERNumericString(((ASN1NumericString)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERNumericString)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERNumericString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERNumericString)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERNumericString(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERNumericString(String paramString) {
    this(paramString, false);
  }
  
  public DERNumericString(String paramString, boolean paramBoolean) {
    super(paramString, paramBoolean);
  }
  
  DERNumericString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
