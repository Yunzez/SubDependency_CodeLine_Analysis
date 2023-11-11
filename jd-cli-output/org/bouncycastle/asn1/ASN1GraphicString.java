package org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class ASN1GraphicString extends ASN1Primitive implements ASN1String {
  static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1GraphicString.class, 25) {
      ASN1Primitive fromImplicitPrimitive(DEROctetString param1DEROctetString) {
        return ASN1GraphicString.createPrimitive(param1DEROctetString.getOctets());
      }
    };
  
  final byte[] contents;
  
  public static ASN1GraphicString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof ASN1GraphicString)
      return (ASN1GraphicString)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof ASN1GraphicString)
        return (ASN1GraphicString)aSN1Primitive; 
    } 
    if (paramObject instanceof byte[])
      try {
        return (ASN1GraphicString)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static ASN1GraphicString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (ASN1GraphicString)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  ASN1GraphicString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    if (null == paramArrayOfbyte)
      throw new NullPointerException("'contents' cannot be null"); 
    this.contents = paramBoolean ? Arrays.clone(paramArrayOfbyte) : paramArrayOfbyte;
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
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 25, this.contents);
  }
  
  final boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof ASN1GraphicString))
      return false; 
    ASN1GraphicString aSN1GraphicString = (ASN1GraphicString)paramASN1Primitive;
    return Arrays.areEqual(this.contents, aSN1GraphicString.contents);
  }
  
  public final int hashCode() {
    return Arrays.hashCode(this.contents);
  }
  
  public final String getString() {
    return Strings.fromByteArray(this.contents);
  }
  
  static ASN1GraphicString createPrimitive(byte[] paramArrayOfbyte) {
    return new DERGraphicString(paramArrayOfbyte, false);
  }
}
