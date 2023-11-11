package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROutputStream;

public class DERSet extends ASN1Set {
  public static org.bouncycastle.asn1.DERSet convert(ASN1Set paramASN1Set) {
    return (org.bouncycastle.asn1.DERSet)paramASN1Set.toDERObject();
  }
  
  private int contentsLength = -1;
  
  public DERSet() {}
  
  public DERSet(ASN1Encodable paramASN1Encodable) {
    super(paramASN1Encodable);
  }
  
  public DERSet(ASN1EncodableVector paramASN1EncodableVector) {
    super(paramASN1EncodableVector, true);
  }
  
  public DERSet(ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(paramArrayOfASN1Encodable, true);
  }
  
  DERSet(boolean paramBoolean, ASN1Encodable[] paramArrayOfASN1Encodable) {
    super(checkSorted(paramBoolean), paramArrayOfASN1Encodable);
  }
  
  private int getContentsLength() throws IOException {
    if (this.contentsLength < 0) {
      int i = this.elements.length;
      int j = 0;
      for (byte b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDERObject();
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
    DEROutputStream dEROutputStream = paramASN1OutputStream.getDERSubStream();
    int i = this.elements.length;
    if (this.contentsLength >= 0 || i > 16) {
      paramASN1OutputStream.writeDL(getContentsLength());
      for (byte b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDERObject();
        aSN1Primitive.encode(dEROutputStream, true);
      } 
    } else {
      int j = 0;
      ASN1Primitive[] arrayOfASN1Primitive = new ASN1Primitive[i];
      byte b;
      for (b = 0; b < i; b++) {
        ASN1Primitive aSN1Primitive = this.elements[b].toASN1Primitive().toDERObject();
        arrayOfASN1Primitive[b] = aSN1Primitive;
        j += aSN1Primitive.encodedLength(true);
      } 
      this.contentsLength = j;
      paramASN1OutputStream.writeDL(j);
      for (b = 0; b < i; b++)
        arrayOfASN1Primitive[b].encode(dEROutputStream, true); 
    } 
  }
  
  ASN1Primitive toDERObject() {
    return this.isSorted ? this : super.toDERObject();
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
  
  private static boolean checkSorted(boolean paramBoolean) {
    if (!paramBoolean)
      throw new IllegalStateException("DERSet elements should always be in sorted order"); 
    return paramBoolean;
  }
}
