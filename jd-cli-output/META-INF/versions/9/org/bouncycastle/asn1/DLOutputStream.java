package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;

class DLOutputStream extends ASN1OutputStream {
  DLOutputStream(OutputStream paramOutputStream) {
    super(paramOutputStream);
  }
  
  org.bouncycastle.asn1.DLOutputStream getDLSubStream() {
    return this;
  }
  
  void writeElements(ASN1Encodable[] paramArrayOfASN1Encodable) throws IOException {
    byte b;
    int i;
    for (b = 0, i = paramArrayOfASN1Encodable.length; b < i; b++)
      paramArrayOfASN1Encodable[b].toASN1Primitive().toDLObject().encode(this, true); 
  }
  
  void writePrimitive(ASN1Primitive paramASN1Primitive, boolean paramBoolean) throws IOException {
    paramASN1Primitive.toDLObject().encode(this, paramBoolean);
  }
  
  void writePrimitives(ASN1Primitive[] paramArrayOfASN1Primitive) throws IOException {
    int i = paramArrayOfASN1Primitive.length;
    for (byte b = 0; b < i; b++)
      paramArrayOfASN1Primitive[b].toDLObject().encode(this, true); 
  }
}
