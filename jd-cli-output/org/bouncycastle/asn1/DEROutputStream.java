package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;

class DEROutputStream extends DLOutputStream {
  DEROutputStream(OutputStream paramOutputStream) {
    super(paramOutputStream);
  }
  
  DEROutputStream getDERSubStream() {
    return this;
  }
  
  void writeElements(ASN1Encodable[] paramArrayOfASN1Encodable) throws IOException {
    byte b = 0;
    int i = paramArrayOfASN1Encodable.length;
    while (b < i) {
      paramArrayOfASN1Encodable[b].toASN1Primitive().toDERObject().encode(this, true);
      b++;
    } 
  }
  
  void writePrimitive(ASN1Primitive paramASN1Primitive, boolean paramBoolean) throws IOException {
    paramASN1Primitive.toDERObject().encode(this, paramBoolean);
  }
  
  void writePrimitives(ASN1Primitive[] paramArrayOfASN1Primitive) throws IOException {
    int i = paramArrayOfASN1Primitive.length;
    for (byte b = 0; b < i; b++)
      paramArrayOfASN1Primitive[b].toDERObject().encode(this, true); 
  }
}
