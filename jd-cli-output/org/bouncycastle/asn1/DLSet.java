package org.bouncycastle.asn1;

import java.io.IOException;

public class DLSet extends ASN1Set {
  private int contentsLength = -1;
  
  public DLSet() {}
  
  public DLSet(ASN1Encodable paramASN1Encodable) {
    super(paramASN1Encodable);
  }
  
  public DLSet(ASN1EncodableVector paramASN1EncodableVector) {
    super(paramASN1EncodableVector, false);
  }
  
  public DLSet(ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(paramArrayOfASN1Encodable, false);
  }
  
  DLSet(boolean paramBoolean, ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(paramBoolean, paramArrayOfASN1Encodable);
  }
  
  private int getContentsLength() throws IOException {
    if (this.contentsLength < 0) {
      int i = this.elements.length;
      int j = 0;
      for (byte b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDLObject();
        j += aSN1Primitive.encodedLength(true);
      } 
      this.contentsLength = j;
    } 
    return this.contentsLength;
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, getContentsLength());
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeIdentifier(paramBoolean, 49);
    DLOutputStream dLOutputStream = paramASN1OutputStream.getDLSubStream();
    int i = this.elements.length;
    if (this.contentsLength >= 0 || i > 16) {
      paramASN1OutputStream.writeDL(getContentsLength());
      for (byte b = 0; b < i; b++)
        dLOutputStream.writePrimitive(this.elements[b].toASN1Primitive(), true); 
    } else {
      int j = 0;
      ASN1Primitive[] arrayOfASN1Primitive = new ASN1Primitive[i];
      byte b;
      for (b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDLObject();
        arrayOfASN1Primitive[b] = aSN1Primitive;
        j += aSN1Primitive.encodedLength(true);
      } 
      this.contentsLength = j;
      paramASN1OutputStream.writeDL(j);
      for (b = 0; b < i; b++)
        dLOutputStream.writePrimitive(arrayOfASN1Primitive[b], true); 
    } 
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}
