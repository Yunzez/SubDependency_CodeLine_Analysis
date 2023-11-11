package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class ASN1IA5String extends ASN1Primitive implements ASN1String {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1IA5String.class, 22) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1IA5String.createPrimitive(param1DEROctetString.getOctets());
      }
    };
  
  final byte[] contents;
  
  public static ASN1IA5String getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1IA5String)
      return (ASN1IA5String)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof ASN1IA5String)
        return (ASN1IA5String)aSN1Primitive; 
    } 
    if (paramObject instanceof byte[])
      try {
        return (ASN1IA5String)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1IA5String getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1IA5String)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  ASN1IA5String(String paramString, boolean paramBoolean) {
    if (paramString == null)
      throw new NullPointerException("'string' cannot be null"); 
    if (paramBoolean && !isIA5String(paramString))
      throw new IllegalArgumentException("'string' contains illegal characters"); 
    this.contents = Strings.toByteArray(paramString);
  }
  
  ASN1IA5String(byte[] paramArrayOfbyte, boolean paramBoolean) {
    this.contents = paramBoolean ? Arrays.clone(paramArrayOfbyte) : paramArrayOfbyte;
  }
  
  public final String getString() {
    return Strings.fromByteArray(this.contents);
  }
  
  public String toString() {
    return getString();
  }
  
  public final byte[] getOctets() {
    return Arrays.clone(this.contents);
  }
  
  final boolean encodeConstructed() {
    return false;
  }
  
  final int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.contents.length);
  }
  
  final void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 22, this.contents);
  }
  
  final boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1IA5String))
      return false; 
    ASN1IA5String aSN1IA5String = (ASN1IA5String)paramASN1Primitive;
    return Arrays.areEqual(this.contents, aSN1IA5String.contents);
  }
  
  public final int hashCode() {
    return Arrays.hashCode(this.contents);
  }
  
  public static boolean isIA5String(String paramString) {
    for (int i = paramString.length() - 1; i >= 0; i--) {
      char c = paramString.charAt(i);
      if (c > '')
        return false; 
    } 
    return true;
  }
  
  static ASN1IA5String createPrimitive(byte[] paramArrayOfbyte) {
    return new DERIA5String(paramArrayOfbyte, false);
  }
}
