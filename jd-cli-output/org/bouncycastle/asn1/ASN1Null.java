package org.bouncycastle.asn1;

import java.io.IOException;

public abstract class ASN1Null extends ASN1Primitive {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Null.class, 5) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1Null.createPrimitive(param1DEROctetString.getOctets());
      }
    };
  
  public static ASN1Null getInstance(Object paramObject) {
    if (paramObject instanceof ASN1Null)
      return (ASN1Null)paramObject; 
    if (paramObject != null)
      try {
        return (ASN1Null)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct NULL from byte[]: " + iOException.getMessage());
      }  
    return null;
  }
  
  public static ASN1Null getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1Null)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public int hashCode() {
    return -1;
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    return !!(paramASN1Primitive instanceof ASN1Null);
  }
  
  public String toString() {
    return "NULL";
  }
  
  static ASN1Null createPrimitive(byte[] paramArrayOfbyte) {
    if (0 != paramArrayOfbyte.length)
      throw new IllegalStateException("malformed NULL encoding encountered"); 
    return DERNull.INSTANCE;
  }
}
