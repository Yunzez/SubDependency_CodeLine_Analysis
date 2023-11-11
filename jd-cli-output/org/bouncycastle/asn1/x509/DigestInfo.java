package org.bouncycastle.asn1.x509;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class DigestInfo extends ASN1Object {
  private byte[] digest;
  
  private AlgorithmIdentifier algId;
  
  public static DigestInfo getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return getInstance(ASN1Sequence.getInstance(paramASN1TaggedObject, paramBoolean));
  }
  
  public static DigestInfo getInstance(Object paramObject) {
    return (paramObject instanceof DigestInfo) ? (DigestInfo)paramObject : ((paramObject != null) ? new DigestInfo(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public DigestInfo(AlgorithmIdentifier paramAlgorithmIdentifier, byte[] paramArrayOfbyte) {
    this.digest = Arrays.clone(paramArrayOfbyte);
    this.algId = paramAlgorithmIdentifier;
  }
  
  public DigestInfo(ASN1Sequence paramASN1Sequence) {
    Enumeration enumeration = paramASN1Sequence.getObjects();
    this.algId = AlgorithmIdentifier.getInstance(enumeration.nextElement());
    this.digest = ASN1OctetString.getInstance(enumeration.nextElement()).getOctets();
  }
  
  public AlgorithmIdentifier getAlgorithmId() {
    return this.algId;
  }
  
  public byte[] getDigest() {
    return Arrays.clone(this.digest);
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    aSN1EncodableVector.add(this.algId);
    aSN1EncodableVector.add(new DEROctetString(this.digest));
    return new DERSequence(aSN1EncodableVector);
  }
}
