package org.bouncycastle.asn1;

import java.io.IOException;

public class ASN1Boolean extends ASN1Primitive {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Boolean.class, 1) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1Boolean.createPrimitive(param1DEROctetString.getOctets());
      }
    };
  
  private static final byte FALSE_VALUE = 0;
  
  private static final byte TRUE_VALUE = -1;
  
  public static final ASN1Boolean FALSE = new ASN1Boolean((byte)0);
  
  public static final ASN1Boolean TRUE = new ASN1Boolean((byte)-1);
  
  private final byte value;
  
  public static ASN1Boolean getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1Boolean)
      return (ASN1Boolean)paramObject; 
    if (paramObject instanceof byte[]) {
      byte[] arrayOfByte = (byte[])paramObject;
      try {
        return (ASN1Boolean)TYPE.fromByteArray(arrayOfByte);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct boolean from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1Boolean getInstance(boolean paramBoolean) {
    return paramBoolean ? TRUE : FALSE;
  }
  
  public static ASN1Boolean getInstance(int paramInt) {
    return (paramInt != 0) ? TRUE : FALSE;
  }
  
  public static ASN1Boolean getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1Boolean)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  private ASN1Boolean(byte paramByte) {
    this.value = paramByte;
  }
  
  public boolean isTrue() {
    return (this.value != 0);
  }
  
  boolean encodeConstructed() {
    return false;
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, 1);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 1, this.value);
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1Boolean))
      return false; 
    ASN1Boolean aSN1Boolean = (ASN1Boolean)paramASN1Primitive;
    return (isTrue() == aSN1Boolean.isTrue());
  }
  
  public int hashCode() {
    return isTrue() ? 1 : 0;
  }
  
  ASN1Primitive toDERObject() {
    return isTrue() ? TRUE : FALSE;
  }
  
  public String toString() {
    return isTrue() ? "TRUE" : "FALSE";
  }
  
  static ASN1Boolean createPrimitive(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length != 1)
      throw new IllegalArgumentException("BOOLEAN value should have 1 byte in it"); 
    byte b = paramArrayOfbyte[0];
    switch (b) {
      case 0:
        return FALSE;
      case -1:
        return TRUE;
    } 
    return new ASN1Boolean(b);
  }
}
