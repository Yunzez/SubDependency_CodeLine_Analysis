package org.bouncycastle.asn1;

import java.io.IOException;

public class BERSet extends ASN1Set {
  public BERSet() {}
  
  public BERSet(ASN1Encodable paramASN1Encodable) {
    super(paramASN1Encodable);
  }
  
  public BERSet(ASN1EncodableVector paramASN1EncodableVector) {
    super(paramASN1EncodableVector, false);
  }
  
  public BERSet(ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(paramArrayOfASN1Encodable, false);
  }
  
  BERSet(boolean paramBoolean, ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(paramBoolean, paramArrayOfASN1Encodable);
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
    paramASN1OutputStream.writeEncodingIL(paramBoolean, 49, this.elements);
  }
}
