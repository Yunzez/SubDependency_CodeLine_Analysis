package META-INF.versions.9.org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class SubjectPublicKeyInfo extends ASN1Object {
  private AlgorithmIdentifier algId;
  
  private ASN1BitString keyData;
  
  public static org.bouncycastle.asn1.x509.SubjectPublicKeyInfo getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return getInstance(ASN1Sequence.getInstance(paramASN1TaggedObject, paramBoolean));
  }
  
  public static org.bouncycastle.asn1.x509.SubjectPublicKeyInfo getInstance(Object paramObject) {
    if (paramObject instanceof org.bouncycastle.asn1.x509.SubjectPublicKeyInfo)
      return (org.bouncycastle.asn1.x509.SubjectPublicKeyInfo)paramObject; 
    if (paramObject != null)
      return new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(ASN1Sequence.getInstance(paramObject)); 
    return null;
  }
  
  public SubjectPublicKeyInfo(AlgorithmIdentifier paramAlgorithmIdentifier, ASN1Encodable paramASN1Encodable) throws IOException {
    this.keyData = new DERBitString(paramASN1Encodable);
    this.algId = paramAlgorithmIdentifier;
  }
  
  public SubjectPublicKeyInfo(AlgorithmIdentifier paramAlgorithmIdentifier, byte[] paramArrayOfbyte) {
    this.keyData = new DERBitString(paramArrayOfbyte);
    this.algId = paramAlgorithmIdentifier;
  }
  
  public SubjectPublicKeyInfo(ASN1Sequence paramASN1Sequence) {
    if (paramASN1Sequence.size() != 2)
      throw new IllegalArgumentException("Bad sequence size: " + paramASN1Sequence
          .size()); 
    Enumeration enumeration = paramASN1Sequence.getObjects();
    this.algId = AlgorithmIdentifier.getInstance(enumeration.nextElement());
    this.keyData = DERBitString.getInstance(enumeration.nextElement());
  }
  
  public AlgorithmIdentifier getAlgorithm() {
    return this.algId;
  }
  
  public AlgorithmIdentifier getAlgorithmId() {
    return this.algId;
  }
  
  public ASN1Primitive parsePublicKey() throws IOException {
    return ASN1Primitive.fromByteArray(this.keyData.getOctets());
  }
  
  public ASN1Primitive getPublicKey() throws IOException {
    return ASN1Primitive.fromByteArray(this.keyData.getOctets());
  }
  
  public ASN1BitString getPublicKeyData() {
    return this.keyData;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    aSN1EncodableVector.add(this.algId);
    aSN1EncodableVector.add(this.keyData);
    return new DERSequence(aSN1EncodableVector);
  }
}
