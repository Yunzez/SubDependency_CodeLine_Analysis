package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.DERNull;

public abstract class ASN1Null extends ASN1Primitive {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1Null.class, 5);
  
  public static org.bouncycastle.asn1.ASN1Null getInstance(Object paramObject) {
    if (paramObject instanceof org.bouncycastle.asn1.ASN1Null)
      return (org.bouncycastle.asn1.ASN1Null)paramObject; 
    if (paramObject != null)
      try {
        return (org.bouncycastle.asn1.ASN1Null)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct NULL from byte[]: " + iOException.getMessage());
      }  
    return null;
  }
  
  public static org.bouncycastle.asn1.ASN1Null getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1Null)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public int hashCode() {
    return -1;
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1Null))
      return false; 
    return true;
  }
  
  public String toString() {
    return "NULL";
  }
  
  static org.bouncycastle.asn1.ASN1Null createPrimitive(byte[] paramArrayOfbyte) {
    if (0 != paramArrayOfbyte.length)
      throw new IllegalStateException("malformed NULL encoding encountered"); 
    return DERNull.INSTANCE;
  }
}
