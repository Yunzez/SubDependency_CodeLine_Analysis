package META-INF.versions.9.org.bouncycastle.asn1.x9;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.X9FieldElement;
import org.bouncycastle.asn1.x9.X9FieldID;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.Arrays;

public class X9Curve extends ASN1Object implements X9ObjectIdentifiers {
  private ECCurve curve;
  
  private byte[] seed;
  
  private ASN1ObjectIdentifier fieldIdentifier = null;
  
  public X9Curve(ECCurve paramECCurve) {
    this(paramECCurve, (byte[])null);
  }
  
  public X9Curve(ECCurve paramECCurve, byte[] paramArrayOfbyte) {
    this.curve = paramECCurve;
    this.seed = Arrays.clone(paramArrayOfbyte);
    setFieldIdentifier();
  }
  
  public X9Curve(X9FieldID paramX9FieldID, BigInteger paramBigInteger1, BigInteger paramBigInteger2, ASN1Sequence paramASN1Sequence) {
    this.fieldIdentifier = paramX9FieldID.getIdentifier();
    if (this.fieldIdentifier.equals(prime_field)) {
      BigInteger bigInteger1 = ((ASN1Integer)paramX9FieldID.getParameters()).getValue();
      BigInteger bigInteger2 = new BigInteger(1, ASN1OctetString.getInstance(paramASN1Sequence.getObjectAt(0)).getOctets());
      BigInteger bigInteger3 = new BigInteger(1, ASN1OctetString.getInstance(paramASN1Sequence.getObjectAt(1)).getOctets());
      this.curve = new ECCurve.Fp(bigInteger1, bigInteger2, bigInteger3, paramBigInteger1, paramBigInteger2);
    } else if (this.fieldIdentifier.equals(characteristic_two_field)) {
      ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(paramX9FieldID.getParameters());
      int i = ((ASN1Integer)aSN1Sequence.getObjectAt(0)).intValueExact();
      ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier)aSN1Sequence.getObjectAt(1);
      int j = 0;
      int k = 0;
      int m = 0;
      if (aSN1ObjectIdentifier.equals(tpBasis)) {
        j = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(2)).intValueExact();
      } else if (aSN1ObjectIdentifier.equals(ppBasis)) {
        ASN1Sequence aSN1Sequence1 = ASN1Sequence.getInstance(aSN1Sequence.getObjectAt(2));
        j = ASN1Integer.getInstance(aSN1Sequence1.getObjectAt(0)).intValueExact();
        k = ASN1Integer.getInstance(aSN1Sequence1.getObjectAt(1)).intValueExact();
        m = ASN1Integer.getInstance(aSN1Sequence1.getObjectAt(2)).intValueExact();
      } else {
        throw new IllegalArgumentException("This type of EC basis is not implemented");
      } 
      BigInteger bigInteger1 = new BigInteger(1, ASN1OctetString.getInstance(paramASN1Sequence.getObjectAt(0)).getOctets());
      BigInteger bigInteger2 = new BigInteger(1, ASN1OctetString.getInstance(paramASN1Sequence.getObjectAt(1)).getOctets());
      this.curve = new ECCurve.F2m(i, j, k, m, bigInteger1, bigInteger2, paramBigInteger1, paramBigInteger2);
    } else {
      throw new IllegalArgumentException("This type of ECCurve is not implemented");
    } 
    if (paramASN1Sequence.size() == 3)
      this.seed = ((DERBitString)paramASN1Sequence.getObjectAt(2)).getBytes(); 
  }
  
  private void setFieldIdentifier() {
    if (ECAlgorithms.isFpCurve(this.curve)) {
      this.fieldIdentifier = prime_field;
    } else if (ECAlgorithms.isF2mCurve(this.curve)) {
      this.fieldIdentifier = characteristic_two_field;
    } else {
      throw new IllegalArgumentException("This type of ECCurve is not implemented");
    } 
  }
  
  public ECCurve getCurve() {
    return this.curve;
  }
  
  public byte[] getSeed() {
    return Arrays.clone(this.seed);
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(3);
    if (this.fieldIdentifier.equals(prime_field)) {
      aSN1EncodableVector.add((new X9FieldElement(this.curve.getA())).toASN1Primitive());
      aSN1EncodableVector.add((new X9FieldElement(this.curve.getB())).toASN1Primitive());
    } else if (this.fieldIdentifier.equals(characteristic_two_field)) {
      aSN1EncodableVector.add((new X9FieldElement(this.curve.getA())).toASN1Primitive());
      aSN1EncodableVector.add((new X9FieldElement(this.curve.getB())).toASN1Primitive());
    } 
    if (this.seed != null)
      aSN1EncodableVector.add(new DERBitString(this.seed)); 
    return new DERSequence(aSN1EncodableVector);
  }
}
