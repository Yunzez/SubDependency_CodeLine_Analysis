package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;

class DERFactory {
  static final DERSequence EMPTY_SEQUENCE = new DERSequence();
  
  static final DERSet EMPTY_SET = new DERSet();
  
  static DERSequence createSequence(ASN1EncodableVector paramASN1EncodableVector) {
    if (paramASN1EncodableVector.size() < 1)
      return EMPTY_SEQUENCE; 
    return new DERSequence(paramASN1EncodableVector);
  }
  
  static DERSet createSet(ASN1EncodableVector paramASN1EncodableVector) {
    if (paramASN1EncodableVector.size() < 1)
      return EMPTY_SET; 
    return new DERSet(paramASN1EncodableVector);
  }
}
