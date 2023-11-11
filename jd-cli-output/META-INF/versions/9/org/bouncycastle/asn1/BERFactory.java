package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.BERSet;

class BERFactory {
  static final BERSequence EMPTY_SEQUENCE = new BERSequence();
  
  static final BERSet EMPTY_SET = new BERSet();
  
  static BERSequence createSequence(ASN1EncodableVector paramASN1EncodableVector) {
    if (paramASN1EncodableVector.size() < 1)
      return EMPTY_SEQUENCE; 
    return new BERSequence(paramASN1EncodableVector);
  }
  
  static BERSet createSet(ASN1EncodableVector paramASN1EncodableVector) {
    if (paramASN1EncodableVector.size() < 1)
      return EMPTY_SET; 
    return new BERSet(paramASN1EncodableVector);
  }
}
