package org.bouncycastle.asn1.misc;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class ScryptParams extends ASN1Object {
  private final byte[] salt;
  
  private final BigInteger costParameter;
  
  private final BigInteger blockSize;
  
  private final BigInteger parallelizationParameter;
  
  private final BigInteger keyLength;
  
  public ScryptParams(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3) {
    this(paramArrayOfbyte, BigInteger.valueOf(paramInt1), BigInteger.valueOf(paramInt2), BigInteger.valueOf(paramInt3), (BigInteger)null);
  }
  
  public ScryptParams(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    this(paramArrayOfbyte, BigInteger.valueOf(paramInt1), BigInteger.valueOf(paramInt2), BigInteger.valueOf(paramInt3), BigInteger.valueOf(paramInt4));
  }
  
  public ScryptParams(byte[] paramArrayOfbyte, BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3, BigInteger paramBigInteger4) {
    this.salt = Arrays.clone(paramArrayOfbyte);
    this.costParameter = paramBigInteger1;
    this.blockSize = paramBigInteger2;
    this.parallelizationParameter = paramBigInteger3;
    this.keyLength = paramBigInteger4;
  }
  
  public static ScryptParams getInstance(Object paramObject) {
    return (paramObject instanceof ScryptParams) ? (ScryptParams)paramObject : ((paramObject != null) ? new ScryptParams(ASN1Sequence.getInstance(paramObject)) : null);
  }
  
  private ScryptParams(ASN1Sequence paramASN1Sequence) {
    if (paramASN1Sequence.size() != 4 && paramASN1Sequence.size() != 5)
      throw new IllegalArgumentException("invalid sequence: size = " + paramASN1Sequence.size()); 
    this.salt = Arrays.clone(ASN1OctetString.getInstance(paramASN1Sequence.getObjectAt(0)).getOctets());
    this.costParameter = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(1)).getValue();
    this.blockSize = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(2)).getValue();
    this.parallelizationParameter = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(3)).getValue();
    if (paramASN1Sequence.size() == 5) {
      this.keyLength = ASN1Integer.getInstance(paramASN1Sequence.getObjectAt(4)).getValue();
    } else {
      this.keyLength = null;
    } 
  }
  
  public byte[] getSalt() {
    return Arrays.clone(this.salt);
  }
  
  public BigInteger getCostParameter() {
    return this.costParameter;
  }
  
  public BigInteger getBlockSize() {
    return this.blockSize;
  }
  
  public BigInteger getParallelizationParameter() {
    return this.parallelizationParameter;
  }
  
  public BigInteger getKeyLength() {
    return this.keyLength;
  }
  
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(5);
    aSN1EncodableVector.add(new DEROctetString(this.salt));
    aSN1EncodableVector.add(new ASN1Integer(this.costParameter));
    aSN1EncodableVector.add(new ASN1Integer(this.blockSize));
    aSN1EncodableVector.add(new ASN1Integer(this.parallelizationParameter));
    if (this.keyLength != null)
      aSN1EncodableVector.add(new ASN1Integer(this.keyLength)); 
    return new DERSequence(aSN1EncodableVector);
  }
}
