package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLOutputStream;

class DEROutputStream extends DLOutputStream {
  DEROutputStream(OutputStream paramOutputStream) {
    super(paramOutputStream);
  }
  
  org.bouncycastle.asn1.DEROutputStream getDERSubStream() {
    return this;
  }
  
  void writeElements(ASN1Encodable[] paramArrayOfASN1Encodable) throws IOException {
    byte b;
    int i;
    for (b = 0, i = paramArrayOfASN1Encodable.length; b < i; b++)
      paramArrayOfASN1Encodable[b].toASN1Primitive().toDERObject().encode(this, true); 
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
