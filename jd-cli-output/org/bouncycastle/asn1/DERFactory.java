package org.bouncycastle.asn1;

class DERFactory {
  static final DERSequence EMPTY_SEQUENCE = new DERSequence();
  
  static final DERSet EMPTY_SET = new DERSet();
  
  static DERSequence createSequence(ASN1EncodableVector paramASN1EncodableVector) {
    return (paramASN1EncodableVector.size() < 1) ? EMPTY_SEQUENCE : new DERSequence(paramASN1EncodableVector);
  }
  
  static DERSet createSet(ASN1EncodableVector paramASN1EncodableVector) {
    return (paramASN1EncodableVector.size() < 1) ? EMPTY_SET : new DERSet(paramASN1EncodableVector);
  }
}
