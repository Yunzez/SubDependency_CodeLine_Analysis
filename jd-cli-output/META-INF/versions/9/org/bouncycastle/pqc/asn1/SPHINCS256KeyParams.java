package META-INF.versions.9.org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class SPHINCS256KeyParams extends ASN1Object {
  private final ASN1Integer version;
  
  private final AlgorithmIdentifier treeDigest;
  
  public SPHINCS256KeyParams(AlgorithmIdentifier paramAlgorithmIdentifier) {
    this.version = new ASN1Integer(0L);
    this.treeDigest = paramAlgorithmIdentifier;
  }
  
  private SPHINCS256KeyParams(ASN1Sequence paramASN1Sequence) {
    this.version = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(0));
    this.treeDigest = AlgorithmIdentifier.getInstance(paramASN1Sequence.getObjectAt(1));
  }
  
  public static final org.bouncycastle.pqc.asn1.SPHINCS256KeyParams getInstance(Object paramObject) {
    if (paramObject instanceof org.bouncycastle.pqc.asn1.SPHINCS256KeyParams)
      return (org.bouncycastle.pqc.asn1.SPHINCS256KeyParams)paramObject; 
    if (paramObject != null)
      return new org.bouncycastle.pqc.asn1.SPHINCS256KeyParams(ASN1Sequence.getInstance(paramObject)); 
    return null;
  }
  
  public AlgorithmIdentifier getTreeDigest() {
    return this.treeDigest;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
    aSN1EncodableVector.add(this.version);
    aSN1EncodableVector.add(this.treeDigest);
    return new DERSequence(aSN1EncodableVector);
  }
}
