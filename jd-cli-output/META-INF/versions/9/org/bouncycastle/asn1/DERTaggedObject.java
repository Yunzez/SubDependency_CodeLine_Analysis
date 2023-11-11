package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;

public class DERTaggedObject extends ASN1TaggedObject {
  public DERTaggedObject(int paramInt, ASN1Encodable paramASN1Encodable) {
    super(true, paramInt, paramASN1Encodable);
  }
  
  public DERTaggedObject(int paramInt1, int paramInt2, ASN1Encodable paramASN1Encodable) {
    super(true, paramInt1, paramInt2, paramASN1Encodable);
  }
  
  public DERTaggedObject(boolean paramBoolean, int paramInt, ASN1Encodable paramASN1Encodable) {
    super(paramBoolean, paramInt, paramASN1Encodable);
  }
  
  public DERTaggedObject(boolean paramBoolean, int paramInt1, int paramInt2, ASN1Encodable paramASN1Encodable) {
    super(paramBoolean, paramInt1, paramInt2, paramASN1Encodable);
  }
  
  DERTaggedObject(int paramInt1, int paramInt2, int paramInt3, ASN1Encodable paramASN1Encodable) {
    super(paramInt1, paramInt2, paramInt3, paramASN1Encodable);
  }
  
  boolean encodeConstructed() {
    return (isExplicit() || this.obj.toASN1Primitive().toDERObject().encodeConstructed());
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    ASN1Primitive aSN1Primitive = this.obj.toASN1Primitive().toDERObject();
    boolean bool = isExplicit();
    int i = aSN1Primitive.encodedLength(bool);
    if (bool)
      i += ASN1OutputStream.getLengthOfDL(i); 
    i += paramBoolean ? ASN1OutputStream.getLengthOfIdentifier(this.tagNo) : 0;
    return i;
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    ASN1Primitive aSN1Primitive = this.obj.toASN1Primitive().toDERObject();
    boolean bool = isExplicit();
    if (paramBoolean) {
      int i = this.tagClass;
      if (bool || aSN1Primitive.encodeConstructed())
        i |= 0x20; 
      paramASN1OutputStream.writeIdentifier(true, i, this.tagNo);
    } 
    if (bool)
      paramASN1OutputStream.writeDL(aSN1Primitive.encodedLength(true)); 
    aSN1Primitive.encode(paramASN1OutputStream.getDERSubStream(), bool);
  }
  
  String getASN1Encoding() {
    return "DER";
  }
  
  ASN1Sequence rebuildConstructed(ASN1Primitive paramASN1Primitive) {
    return new DERSequence(paramASN1Primitive);
  }
  
  ASN1TaggedObject replaceTag(int paramInt1, int paramInt2) {
    return new org.bouncycastle.asn1.DERTaggedObject(this.explicitness, paramInt1, paramInt2, this.obj);
  }
  
  ASN1Primitive toDERObject() {
    return this;
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}
