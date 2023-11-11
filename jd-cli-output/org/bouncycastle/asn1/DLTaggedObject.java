package org.bouncycastle.asn1;

import java.io.IOException;

public class DLTaggedObject extends ASN1TaggedObject {
  public DLTaggedObject(int paramInt, ASN1Encodable paramASN1Encodable) {
    super(true, paramInt, paramASN1Encodable);
  }
  
  public DLTaggedObject(int paramInt1, int paramInt2, ASN1Encodable paramASN1Encodable) {
    super(true, paramInt1, paramInt2, paramASN1Encodable);
  }
  
  public DLTaggedObject(boolean paramBoolean, int paramInt, ASN1Encodable paramASN1Encodable) {
    super(paramBoolean, paramInt, paramASN1Encodable);
  }
  
  public DLTaggedObject(boolean paramBoolean, int paramInt1, int paramInt2, ASN1Encodable paramASN1Encodable) {
    super(paramBoolean, paramInt1, paramInt2, paramASN1Encodable);
  }
  
  DLTaggedObject(int paramInt1, int paramInt2, int paramInt3, ASN1Encodable paramASN1Encodable) {
    super(paramInt1, paramInt2, paramInt3, paramASN1Encodable);
  }
  
  boolean encodeConstructed() {
    return (isExplicit() || this.obj.toASN1Primitive().toDLObject().encodeConstructed());
  }
  
  int encodedLength(boolean paramBoolean) throws IOException {
    ASN1Primitive aSN1Primitive = this.obj.toASN1Primitive().toDLObject();
    boolean bool = isExplicit();
    int i = aSN1Primitive.encodedLength(bool);
    if (bool)
      i += ASN1OutputStream.getLengthOfDL(i); 
    i += paramBoolean ? ASN1OutputStream.getLengthOfIdentifier(this.tagNo) : 0;
    return i;
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    ASN1Primitive aSN1Primitive = this.obj.toASN1Primitive().toDLObject();
    boolean bool = isExplicit();
    if (paramBoolean) {
      int i = this.tagClass;
      if (bool || aSN1Primitive.encodeConstructed())
        i |= 0x20; 
      paramASN1OutputStream.writeIdentifier(true, i, this.tagNo);
    } 
    if (bool)
      paramASN1OutputStream.writeDL(aSN1Primitive.encodedLength(true)); 
    aSN1Primitive.encode(paramASN1OutputStream.getDLSubStream(), bool);
  }
  
  String getASN1Encoding() {
    return "DL";
  }
  
  ASN1Sequence rebuildConstructed(ASN1Primitive paramASN1Primitive) {
    return new DLSequence(paramASN1Primitive);
  }
  
  ASN1TaggedObject replaceTag(int paramInt1, int paramInt2) {
    return new DLTaggedObject(this.explicitness, paramInt1, paramInt2, this.obj);
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}