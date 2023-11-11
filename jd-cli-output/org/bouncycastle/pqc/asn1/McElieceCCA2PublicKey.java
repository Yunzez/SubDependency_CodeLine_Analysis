package org.bouncycastle.pqc.asn1;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class McElieceCCA2PublicKey extends ASN1Object {
  private final int n;
  
  private final int t;
  
  private final GF2Matrix g;
  
  private final AlgorithmIdentifier digest;
  
  public McElieceCCA2PublicKey(int paramInt1, int paramInt2, GF2Matrix paramGF2Matrix, AlgorithmIdentifier paramAlgorithmIdentifier) {
    this.n = paramInt1;
    this.t = paramInt2;
    this.g = new GF2Matrix(paramGF2Matrix.getEncoded());
    this.digest = paramAlgorithmIdentifier;
  }
  
  private McElieceCCA2PublicKey(ASN1Sequence paramASN1Sequence) {
    this.n = ((ASN1Integer)paramASN1Sequence.getObjectAt(0)).intValueExact();
    this.t = ((ASN1Integer)paramASN1Sequence.getObjectAt(1)).intValueExact();
    this.g = new GF2Matrix(((ASN1OctetString)paramASN1Sequence.getObjectAt(2)).getOctets());
    this.digest = AlgorithmIdentifier.getInstance(paramASN1Sequence.getObjectAt(3));
  }
  
  public int getN() {
    return this.n;
  }
  
  public int getT() {
    return this.t;
  }
  
  public GF2Matrix getG() {
    return this.g;
  }
  
  public AlgorithmIdentifier getDigest() {
    return this.digest;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
    aSN1EncodableVector.add(new ASN1Integer(this.n));
    aSN1EncodableVector.add(new ASN1Integer(this.t));
    aSN1EncodableVector.add(new DEROctetString(this.g.getEncoded()));
    aSN1EncodableVector.add(this.digest);
    return new DERSequence(aSN1EncodableVector);
  }
  
  public static McElieceCCA2PublicKey getInstance(Object paramObject) {
    return (paramObject instanceof McElieceCCA2PublicKey) ? (McElieceCCA2PublicKey)paramObject : ((paramObject != null) ? new McElieceCCA2PublicKey(ASN1Sequence.getInstance(paramObject)) : null);
  }
}
