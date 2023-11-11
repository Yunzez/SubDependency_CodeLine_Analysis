package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

public abstract class ASN1Primitive extends ASN1Object {
  public void encodeTo(OutputStream paramOutputStream) throws IOException {
    ASN1OutputStream aSN1OutputStream = ASN1OutputStream.create(paramOutputStream);
    aSN1OutputStream.writePrimitive(this, true);
    aSN1OutputStream.flushInternal();
  }
  
  public void encodeTo(OutputStream paramOutputStream, String paramString) throws IOException {
    ASN1OutputStream aSN1OutputStream = ASN1OutputStream.create(paramOutputStream, paramString);
    aSN1OutputStream.writePrimitive(this, true);
    aSN1OutputStream.flushInternal();
  }
  
  public static ASN1Primitive fromByteArray(byte[] paramArrayOfbyte) throws IOException {
    ASN1InputStream aSN1InputStream = new ASN1InputStream(paramArrayOfbyte);
    try {
      ASN1Primitive aSN1Primitive = aSN1InputStream.readObject();
      if (aSN1InputStream.available() != 0)
        throw new IOException("Extra data detected in stream"); 
      return aSN1Primitive;
    } catch (ClassCastException classCastException) {
      throw new IOException("cannot recognise object in stream");
    } 
  }
  
  public final boolean equals(Object paramObject) {
    return (this == paramObject) ? true : ((paramObject instanceof ASN1Encodable && asn1Equals(((ASN1Encodable)paramObject).toASN1Primitive())));
  }
  
  public final boolean equals(ASN1Encodable paramASN1Encodable) {
    return (this == paramASN1Encodable || (null != paramASN1Encodable && asn1Equals(paramASN1Encodable.toASN1Primitive())));
  }
  
  public final boolean equals(ASN1Primitive paramASN1Primitive) {
    return (this == paramASN1Primitive || asn1Equals(paramASN1Primitive));
  }
  
  public final ASN1Primitive toASN1Primitive() {
    return this;
  }
  
  ASN1Primitive toDERObject() {
    return this;
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
  
  public abstract int hashCode();
  
  abstract boolean encodeConstructed();
  
  abstract int encodedLength(boolean paramBoolean) throws IOException;
  
  abstract void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException;
  
  abstract boolean asn1Equals(ASN1Primitive paramASN1Primitive);
}
