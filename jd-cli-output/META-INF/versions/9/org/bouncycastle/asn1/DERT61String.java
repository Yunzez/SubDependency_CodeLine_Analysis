package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1T61String;
import org.bouncycastle.asn1.ASN1TaggedObject;

public class DERT61String extends ASN1T61String {
  public static org.bouncycastle.asn1.DERT61String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.DERT61String)
      return (org.bouncycastle.asn1.DERT61String)paramObject; 
    if (paramObject instanceof ASN1T61String)
      return new org.bouncycastle.asn1.DERT61String(((ASN1T61String)paramObject).contents, false); 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.DERT61String)fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.DERT61String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
    if (paramBoolean || aSN1Primitive instanceof org.bouncycastle.asn1.DERT61String)
      return getInstance(aSN1Primitive); 
    return new org.bouncycastle.asn1.DERT61String(ASN1OctetString.getInstance(aSN1Primitive).getOctets(), true);
  }
  
  public DERT61String(String paramString) {
    super(paramString);
  }
  
  public DERT61String(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, true);
  }
  
  DERT61String(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
}
