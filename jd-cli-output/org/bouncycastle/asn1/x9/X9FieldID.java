package org.bouncycastle.asn1.x9;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class X9FieldID extends ASN1Object implements X9ObjectIdentifiers {
  private ASN1ObjectIdentifier id = prime_field;
  
  private ASN1Primitive parameters;
  
  public X9FieldID(BigInteger paramBigInteger) {
    this.parameters = new ASN1Integer(paramBigInteger);
  }
  
  public X9FieldID(int paramInt1, int paramInt2) {
    this(paramInt1, paramInt2, 0, 0);
  }
  
  public X9FieldID(int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
    aSN1EncodableVector.add(new ASN1Integer(paramInt1));
    if (paramInt3 == 0) {
      if (paramInt4 != 0)
        throw new IllegalArgumentException("inconsistent k values"); 
      aSN1EncodableVector.add(tpBasis);
      aSN1EncodableVector.add(new ASN1Integer(paramInt2));
    } else {
      if (paramInt3 <= paramInt2 || paramInt4 <= paramInt3)
        throw new IllegalArgumentException("inconsistent k values"); 
      aSN1EncodableVector.add(ppBasis);
      ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector(3);
      aSN1EncodableVector1.add(new ASN1Integer(paramInt2));
      aSN1EncodableVector1.add(new ASN1Integer(paramInt3));
      aSN1EncodableVector1.add(new ASN1Integer(paramInt4));
      aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector1));
    } 
    this.parameters = new DERSequence(aSN1EncodableVector);
  }
  
  private X9FieldID(ASN1Sequence paramASN1Sequence) {
    this.parameters = paramASN1Sequence.getObjectAt(1).toASN1Primitive();
  }
  
  public static X9FieldID getInstance(Object paramObject) {
    return (paramObject instanceof X9FieldID) ? (X9FieldID)paramObject : ((paramObject != null) ? new X9FieldID(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  public ASN1ObjectIdentifier getIdentifier() {
    return this.id;
  }
  
  public ASN1Primitive getParameters() {
    return this.parameters;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
    aSN1EncodableVector.add(this.id);
    aSN1EncodableVector.add(this.parameters);
    return new DERSequence(aSN1EncodableVector);
  }
}
