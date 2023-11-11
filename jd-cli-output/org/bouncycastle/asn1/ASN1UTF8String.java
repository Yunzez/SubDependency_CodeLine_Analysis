package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class ASN1UTF8String extends ASN1Primitive implements ASN1String {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1UTF8String.class, 12) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1UTF8String.createPrimitive(param1DEROctetString.getOctets());
      }
    };
  
  final byte[] contents;
  
  public static ASN1UTF8String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1UTF8String)
      return (ASN1UTF8String)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof ASN1UTF8String)
        return (ASN1UTF8String)aSN1Primitive; 
    } 
    if (paramObject instanceof byte[])
      try {
        return (ASN1UTF8String)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1UTF8String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1UTF8String)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  ASN1UTF8String(String paramString) {
    this(Strings.toUTF8ByteArray(paramString), false);
  }
  
  ASN1UTF8String(byte[] paramArrayOfbyte, boolean paramBoolean) {
    this.contents = paramBoolean ? Arrays.clone(paramArrayOfbyte) : paramArrayOfbyte;
  }
  
  public final String getString() {
    return Strings.fromUTF8ByteArray(this.contents);
  }
  
  public String toString() {
    return getString();
  }
  
  public final int hashCode() {
    return Arrays.hashCode(this.contents);
  }
  
  final boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1UTF8String))
      return false; 
    ASN1UTF8String aSN1UTF8String = (ASN1UTF8String)paramASN1Primitive;
    return Arrays.areEqual(this.contents, aSN1UTF8String.contents);
  }
  
  final boolean encodeConstructed() {
    return false;
  }
  
  final int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.contents.length);
  }
  
  final void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 12, this.contents);
  }
  
  static ASN1UTF8String createPrimitive(byte[] paramArrayOfbyte) {
    return new DERUTF8String(paramArrayOfbyte, false);
  }
}
