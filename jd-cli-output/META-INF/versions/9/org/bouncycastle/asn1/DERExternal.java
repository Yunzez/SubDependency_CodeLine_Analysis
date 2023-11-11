package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1External;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERFactory;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;

public class DERExternal extends ASN1External {
  public DERExternal(ASN1EncodableVector paramASN1EncodableVector) {
    this(DERFactory.createSequence(paramASN1EncodableVector));
  }
  
  public DERExternal(DERSequence paramDERSequence) {
    super(paramDERSequence);
  }
  
  public DERExternal(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Integer paramASN1Integer, ASN1Primitive paramASN1Primitive, DERTaggedObject paramDERTaggedObject) {
    super(paramASN1ObjectIdentifier, paramASN1Integer, paramASN1Primitive, paramDERTaggedObject);
  }
  
  public DERExternal(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Integer paramASN1Integer, ASN1Primitive paramASN1Primitive1, int paramInt, ASN1Primitive paramASN1Primitive2) {
    super(paramASN1ObjectIdentifier, paramASN1Integer, paramASN1Primitive1, paramInt, paramASN1Primitive2);
  }
  
  ASN1Sequence buildSequence() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(4);
    if (this.directReference != null)
      aSN1EncodableVector.add(this.directReference); 
    if (this.indirectReference != null)
      aSN1EncodableVector.add(this.indirectReference); 
    if (this.dataValueDescriptor != null)
      aSN1EncodableVector.add(this.dataValueDescriptor.toDERObject()); 
    aSN1EncodableVector.add(new DERTaggedObject((0 == this.encoding), this.encoding, this.externalContent));
    return new DERSequence(aSN1EncodableVector);
  }
  
  ASN1Primitive toDERObject() {
    return this;
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}
