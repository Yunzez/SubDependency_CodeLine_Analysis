package org.bouncycastle.crypto.signers;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

public class StandardDSAEncoding implements DSAEncoding {
  public static final StandardDSAEncoding INSTANCE = new StandardDSAEncoding();
  
  public byte[] encode(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3) throws IOException {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
    encodeValue(paramBigInteger1, aSN1EncodableVector, paramBigInteger2);
    encodeValue(paramBigInteger1, aSN1EncodableVector, paramBigInteger3);
    return (new DERSequence(aSN1EncodableVector)).getEncoded("DER");
  }
  
  public BigInteger[] decode(BigInteger paramBigInteger, byte[] paramArrayOfbyte) throws IOException {
    ASN1Sequence aSN1Sequence = (ASN1Sequence)ASN1Primitive.fromByteArray(paramArrayOfbyte);
    if (aSN1Sequence.size() == 2) {
      BigInteger bigInteger1 = decodeValue(paramBigInteger, aSN1Sequence, 0);
      BigInteger bigInteger2 = decodeValue(paramBigInteger, aSN1Sequence, 1);
      byte[] arrayOfByte = encode(paramBigInteger, bigInteger1, bigInteger2);
      if (Arrays.areEqual(arrayOfByte, paramArrayOfbyte))
        return new BigInteger[] { bigInteger1, bigInteger2 }; 
    } 
    throw new IllegalArgumentException("Malformed signature");
  }
  
  protected BigInteger checkValue(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (paramBigInteger2.signum() < 0 || (null != paramBigInteger1 && paramBigInteger2.compareTo(paramBigInteger1) >= 0))
      throw new IllegalArgumentException("Value out of range"); 
    return paramBigInteger2;
  }
  
  protected BigInteger decodeValue(BigInteger paramBigInteger, ASN1Sequence paramASN1Sequence, int paramInt) {
    return checkValue(paramBigInteger, ((ASN1Integer)paramASN1Sequence.getObjectAt(paramInt)).getValue());
  }
  
  protected void encodeValue(BigInteger paramBigInteger1, ASN1EncodableVector paramASN1EncodableVector, BigInteger paramBigInteger2) {
    paramASN1EncodableVector.add(new ASN1Integer(checkValue(paramBigInteger1, paramBigInteger2)));
  }
}
