package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSet;

class DLFactory {
  static final DLSequence EMPTY_SEQUENCE = new DLSequence();
  
  static final DLSet EMPTY_SET = new DLSet();
  
  static DLSequence createSequence(ASN1EncodableVector paramASN1EncodableVector) {
    if (paramASN1EncodableVector.size() < 1)
      return EMPTY_SEQUENCE; 
    return new DLSequence(paramASN1EncodableVector);
  }
  
  static DLSet createSet(ASN1EncodableVector paramASN1EncodableVector) {
    if (paramASN1EncodableVector.size() < 1)
      return EMPTY_SET; 
    return new DLSet(paramASN1EncodableVector);
  }
}
