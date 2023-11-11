package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class PlainDSAEncoding implements DSAEncoding {
  public static final PlainDSAEncoding INSTANCE = new PlainDSAEncoding();
  
  public byte[] encode(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3) {
    int i = BigIntegers.getUnsignedByteLength(paramBigInteger1);
    byte[] arrayOfByte = new byte[i * 2];
    encodeValue(paramBigInteger1, paramBigInteger2, arrayOfByte, 0, i);
    encodeValue(paramBigInteger1, paramBigInteger3, arrayOfByte, i, i);
    return arrayOfByte;
  }
  
  public BigInteger[] decode(BigInteger paramBigInteger, byte[] paramArrayOfbyte) {
    int i = BigIntegers.getUnsignedByteLength(paramBigInteger);
    if (paramArrayOfbyte.length != i * 2)
      throw new IllegalArgumentException("Encoding has incorrect length"); 
    return new BigInteger[] { decodeValue(paramBigInteger, paramArrayOfbyte, 0, i), decodeValue(paramBigInteger, paramArrayOfbyte, i, i) };
  }
  
  protected BigInteger checkValue(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (paramBigInteger2.signum() < 0 || paramBigInteger2.compareTo(paramBigInteger1) >= 0)
      throw new IllegalArgumentException("Value out of range"); 
    return paramBigInteger2;
  }
  
  protected BigInteger decodeValue(BigInteger paramBigInteger, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = Arrays.copyOfRange(paramArrayOfbyte, paramInt1, paramInt1 + paramInt2);
    return checkValue(paramBigInteger, new BigInteger(1, arrayOfByte));
  }
  
  private void encodeValue(BigInteger paramBigInteger1, BigInteger paramBigInteger2, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = checkValue(paramBigInteger1, paramBigInteger2).toByteArray();
    int i = Math.max(0, arrayOfByte.length - paramInt2);
    int j = arrayOfByte.length - i;
    int k = paramInt2 - j;
    Arrays.fill(paramArrayOfbyte, paramInt1, paramInt1 + k, (byte)0);
    System.arraycopy(arrayOfByte, i, paramArrayOfbyte, paramInt1 + k, j);
  }
}
