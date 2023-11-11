package org.bouncycastle.asn1;

import java.io.IOException;

public class BERSequence extends ASN1Sequence {
  public BERSequence() {}
  
  public BERSequence(ASN1Encodable paramASN1Encodable) {
    super(paramASN1Encodable);
  }
  
  public BERSequence(ASN1EncodableVector paramASN1EncodableVector) {
    super(paramASN1EncodableVector);
  }
  
  public BERSequence(ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(paramArrayOfASN1Encodable);
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    int i = paramBoolean ? 4 : 3;
    byte b = 0;
    int j = this.elements.length;
    while (b < j) {
      ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive();
      i += aSN1Primitive.encodedLength(true);
      b++;
    } 
    return i;
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingIL(paramBoolean, 48, this.elements);
  }
  
  ASN1BitString toASN1BitString() {
    return new BERBitString(getConstructedBitStrings());
  }
  
  ASN1External toASN1External() {
    return ((ASN1Sequence)toDLObject()).toASN1External();
  }
  
  ASN1OctetString toASN1OctetString() {
    return new BEROctetString(getConstructedOctetStrings());
  }
  
  ASN1Set toASN1Set() {
    return new BERSet(false, toArrayInternal());
  }
}
