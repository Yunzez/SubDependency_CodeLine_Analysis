package org.bouncycastle.asn1;

import java.io.IOException;

public class DLApplicationSpecific extends ASN1ApplicationSpecific {
  public DLApplicationSpecific(int paramInt, byte[] paramArrayOfbyte) {
    super(new DLTaggedObject(false, 64, paramInt, new DEROctetString(paramArrayOfbyte)));
  }
  
  public DLApplicationSpecific(int paramInt, ASN1Encodable paramASN1Encodable) throws IOException {
    this(true, paramInt, paramASN1Encodable);
  }
  
  public DLApplicationSpecific(boolean paramBoolean, int paramInt, ASN1Encodable paramASN1Encodable) throws IOException {
    super(new DLTaggedObject(paramBoolean, 64, paramInt, paramASN1Encodable));
  }
  
  public DLApplicationSpecific(int paramInt, ASN1EncodableVector paramASN1EncodableVector) {
    super(new DLTaggedObject(false, 64, paramInt, DLFactory.createSequence(paramASN1EncodableVector)));
  }
  
  DLApplicationSpecific(ASN1TaggedObject paramASN1TaggedObject) {
    super(paramASN1TaggedObject);
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}
