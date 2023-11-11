package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Integers;

public class DHPublicKeyParameters extends DHKeyParameters {
  private static final BigInteger ONE = BigInteger.valueOf(1L);
  
  private static final BigInteger TWO = BigInteger.valueOf(2L);
  
  private BigInteger y;
  
  public DHPublicKeyParameters(BigInteger paramBigInteger, DHParameters paramDHParameters) {
    super(false, paramDHParameters);
    this.y = validate(paramBigInteger, paramDHParameters);
  }
  
  private BigInteger validate(BigInteger paramBigInteger, DHParameters paramDHParameters) {
    if (paramBigInteger == null)
      throw new NullPointerException("y value cannot be null"); 
    BigInteger bigInteger1 = paramDHParameters.getP();
    if (paramBigInteger.compareTo(TWO) < 0 || paramBigInteger.compareTo(bigInteger1.subtract(TWO)) > 0)
      throw new IllegalArgumentException("invalid DH public key"); 
    BigInteger bigInteger2 = paramDHParameters.getQ();
    if (bigInteger2 == null)
      return paramBigInteger; 
    if (bigInteger1.testBit(0) && bigInteger1.bitLength() - 1 == bigInteger2.bitLength() && bigInteger1.shiftRight(1).equals(bigInteger2)) {
      if (1 == legendre(paramBigInteger, bigInteger1))
        return paramBigInteger; 
    } else if (ONE.equals(paramBigInteger.modPow(bigInteger2, bigInteger1))) {
      return paramBigInteger;
    } 
    throw new IllegalArgumentException("Y value does not appear to be in correct group");
  }
  
  public BigInteger getY() {
    return this.y;
  }
  
  public int hashCode() {
    return this.y.hashCode() ^ super.hashCode();
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof DHPublicKeyParameters))
      return false; 
    DHPublicKeyParameters dHPublicKeyParameters = (DHPublicKeyParameters)paramObject;
    return (dHPublicKeyParameters.getY().equals(this.y) && super.equals(paramObject));
  }
  
  private static int legendre(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    int i = paramBigInteger2.bitLength();
    int[] arrayOfInt1 = Nat.fromBigInteger(i, paramBigInteger1);
    int[] arrayOfInt2 = Nat.fromBigInteger(i, paramBigInteger2);
    int j = 0;
    int k = arrayOfInt2.length;
    while (true) {
      while (arrayOfInt1[0] == 0)
        Nat.shiftDownWord(k, arrayOfInt1, 0); 
      int m = Integers.numberOfTrailingZeros(arrayOfInt1[0]);
      if (m > 0) {
        Nat.shiftDownBits(k, arrayOfInt1, m, 0);
        int i1 = arrayOfInt2[0];
        j ^= (i1 ^ i1 >>> 1) & m << 1;
      } 
      int n = Nat.compare(k, arrayOfInt1, arrayOfInt2);
      if (n == 0)
        return Nat.isOne(k, arrayOfInt2) ? (1 - (j & 0x2)) : 0; 
      if (n < 0) {
        j ^= arrayOfInt1[0] & arrayOfInt2[0];
        int[] arrayOfInt = arrayOfInt1;
        arrayOfInt1 = arrayOfInt2;
        arrayOfInt2 = arrayOfInt;
      } 
      while (arrayOfInt1[k - 1] == 0)
        k--; 
      Nat.sub(k, arrayOfInt1, arrayOfInt2, arrayOfInt1);
    } 
  }
}
