package org.bouncycastle.asn1;

import java.io.IOException;

abstract class ASN1UniversalType extends ASN1Type {
  final ASN1Tag tag;
  
  ASN1UniversalType(Class paramClass, int paramInt) {
    super(paramClass);
    this.tag = ASN1Tag.create(0, paramInt);
  }
  
  final ASN1Primitive checkedCast(ASN1Primitive paramASN1Primitive) {
    if (this.javaClass.isInstance(paramASN1Primitive))
      return paramASN1Primitive; 
    throw new IllegalStateException("unexpected object: " + paramASN1Primitive.getClass().getName());
  }
  
  ASN1Primitive fromImplicitPrimitive(DEROctetString paramDEROctetString) {
    throw new IllegalStateException("unexpected implicit primitive encoding");
  }
  
  ASN1Primitive fromImplicitConstructed(ASN1Sequence paramASN1Sequence) {
    throw new IllegalStateException("unexpected implicit constructed encoding");
  }
  
  final ASN1Primitive fromByteArray(byte[] paramArrayOfbyte) throws IOException {
    return checkedCast(ASN1Primitive.fromByteArray(paramArrayOfbyte));
  }
  
  final ASN1Primitive getContextInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    if (128 != paramASN1TaggedObject.getTagClass())
      throw new IllegalStateException("this method only valid for CONTEXT_SPECIFIC tags"); 
    return checkedCast(paramASN1TaggedObject.getBaseUniversal(paramBoolean, this));
  }
  
  final ASN1Tag getTag() {
    return this.tag;
  }
}
