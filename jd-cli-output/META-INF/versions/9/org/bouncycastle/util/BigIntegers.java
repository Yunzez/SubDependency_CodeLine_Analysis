package META-INF.versions.9.org.bouncycastle.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;

public final class BigIntegers {
  public static final BigInteger ZERO = BigInteger.valueOf(0L);
  
  public static final BigInteger ONE = BigInteger.valueOf(1L);
  
  public static final BigInteger TWO = BigInteger.valueOf(2L);
  
  private static final BigInteger THREE = BigInteger.valueOf(3L);
  
  private static final int MAX_ITERATIONS = 1000;
  
  public static byte[] asUnsignedByteArray(BigInteger paramBigInteger) {
    byte[] arrayOfByte = paramBigInteger.toByteArray();
    if (arrayOfByte[0] == 0 && arrayOfByte.length != 1) {
      byte[] arrayOfByte1 = new byte[arrayOfByte.length - 1];
      System.arraycopy(arrayOfByte, 1, arrayOfByte1, 0, arrayOfByte1.length);
      return arrayOfByte1;
    } 
    return arrayOfByte;
  }
  
  public static byte[] asUnsignedByteArray(int paramInt, BigInteger paramBigInteger) {
    byte[] arrayOfByte1 = paramBigInteger.toByteArray();
    if (arrayOfByte1.length == paramInt)
      return arrayOfByte1; 
    byte b = (arrayOfByte1[0] == 0 && arrayOfByte1.length != 1) ? 1 : 0;
    int i = arrayOfByte1.length - b;
    if (i > paramInt)
      throw new IllegalArgumentException("standard length exceeded for value"); 
    byte[] arrayOfByte2 = new byte[paramInt];
    System.arraycopy(arrayOfByte1, b, arrayOfByte2, arrayOfByte2.length - i, i);
    return arrayOfByte2;
  }
  
  public static void asUnsignedByteArray(BigInteger paramBigInteger, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = paramBigInteger.toByteArray();
    if (arrayOfByte.length == paramInt2) {
      System.arraycopy(arrayOfByte, 0, paramArrayOfbyte, paramInt1, paramInt2);
      return;
    } 
    byte b = (arrayOfByte[0] == 0 && arrayOfByte.length != 1) ? 1 : 0;
    int i = arrayOfByte.length - b;
    if (i > paramInt2)
      throw new IllegalArgumentException("standard length exceeded for value"); 
    int j = paramInt2 - i;
    Arrays.fill(paramArrayOfbyte, paramInt1, paramInt1 + j, (byte)0);
    System.arraycopy(arrayOfByte, b, paramArrayOfbyte, paramInt1 + j, i);
  }
  
  public static BigInteger createRandomInRange(BigInteger paramBigInteger1, BigInteger paramBigInteger2, SecureRandom paramSecureRandom) {
    int i = paramBigInteger1.compareTo(paramBigInteger2);
    if (i >= 0) {
      if (i > 0)
        throw new IllegalArgumentException("'min' may not be greater than 'max'"); 
      return paramBigInteger1;
    } 
    if (paramBigInteger1.bitLength() > paramBigInteger2.bitLength() / 2)
      return createRandomInRange(ZERO, paramBigInteger2.subtract(paramBigInteger1), paramSecureRandom).add(paramBigInteger1); 
    for (byte b = 0; b < 'Ϩ'; b++) {
      BigInteger bigInteger = createRandomBigInteger(paramBigInteger2.bitLength(), paramSecureRandom);
      if (bigInteger.compareTo(paramBigInteger1) >= 0 && bigInteger.compareTo(paramBigInteger2) <= 0)
        return bigInteger; 
    } 
    return createRandomBigInteger(paramBigInteger2.subtract(paramBigInteger1).bitLength() - 1, paramSecureRandom).add(paramBigInteger1);
  }
  
  public static BigInteger fromUnsignedByteArray(byte[] paramArrayOfbyte) {
    return new BigInteger(1, paramArrayOfbyte);
  }
  
  public static BigInteger fromUnsignedByteArray(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = paramArrayOfbyte;
    if (paramInt1 != 0 || paramInt2 != paramArrayOfbyte.length) {
      arrayOfByte = new byte[paramInt2];
      System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte, 0, paramInt2);
    } 
    return new BigInteger(1, arrayOfByte);
  }
  
  public static byte byteValueExact(BigInteger paramBigInteger) {
    if (paramBigInteger.bitLength() > 7)
      throw new ArithmeticException("BigInteger out of int range"); 
    return paramBigInteger.byteValue();
  }
  
  public static short shortValueExact(BigInteger paramBigInteger) {
    if (paramBigInteger.bitLength() > 15)
      throw new ArithmeticException("BigInteger out of int range"); 
    return paramBigInteger.shortValue();
  }
  
  public static int intValueExact(BigInteger paramBigInteger) {
    if (paramBigInteger.bitLength() > 31)
      throw new ArithmeticException("BigInteger out of int range"); 
    return paramBigInteger.intValue();
  }
  
  public static long longValueExact(BigInteger paramBigInteger) {
    if (paramBigInteger.bitLength() > 63)
      throw new ArithmeticException("BigInteger out of long range"); 
    return paramBigInteger.longValue();
  }
  
  public static BigInteger modOddInverse(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (!paramBigInteger1.testBit(0))
      throw new IllegalArgumentException("'M' must be odd"); 
    if (paramBigInteger1.signum() != 1)
      throw new ArithmeticException("BigInteger: modulus not positive"); 
    if (paramBigInteger2.signum() < 0 || paramBigInteger2.compareTo(paramBigInteger1) >= 0)
      paramBigInteger2 = paramBigInteger2.mod(paramBigInteger1); 
    int i = paramBigInteger1.bitLength();
    int[] arrayOfInt1 = Nat.fromBigInteger(i, paramBigInteger1);
    int[] arrayOfInt2 = Nat.fromBigInteger(i, paramBigInteger2);
    int j = arrayOfInt1.length;
    int[] arrayOfInt3 = Nat.create(j);
    if (0 == Mod.modOddInverse(arrayOfInt1, arrayOfInt2, arrayOfInt3))
      throw new ArithmeticException("BigInteger not invertible."); 
    return Nat.toBigInteger(j, arrayOfInt3);
  }
  
  public static BigInteger modOddInverseVar(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (!paramBigInteger1.testBit(0))
      throw new IllegalArgumentException("'M' must be odd"); 
    if (paramBigInteger1.signum() != 1)
      throw new ArithmeticException("BigInteger: modulus not positive"); 
    if (paramBigInteger1.equals(ONE))
      return ZERO; 
    if (paramBigInteger2.signum() < 0 || paramBigInteger2.compareTo(paramBigInteger1) >= 0)
      paramBigInteger2 = paramBigInteger2.mod(paramBigInteger1); 
    if (paramBigInteger2.equals(ONE))
      return ONE; 
    int i = paramBigInteger1.bitLength();
    int[] arrayOfInt1 = Nat.fromBigInteger(i, paramBigInteger1);
    int[] arrayOfInt2 = Nat.fromBigInteger(i, paramBigInteger2);
    int j = arrayOfInt1.length;
    int[] arrayOfInt3 = Nat.create(j);
    if (!Mod.modOddInverseVar(arrayOfInt1, arrayOfInt2, arrayOfInt3))
      throw new ArithmeticException("BigInteger not invertible."); 
    return Nat.toBigInteger(j, arrayOfInt3);
  }
  
  public static int getUnsignedByteLength(BigInteger paramBigInteger) {
    if (paramBigInteger.equals(ZERO))
      return 1; 
    return (paramBigInteger.bitLength() + 7) / 8;
  }
  
  public static BigInteger createRandomBigInteger(int paramInt, SecureRandom paramSecureRandom) {
    return new BigInteger(1, createRandom(paramInt, paramSecureRandom));
  }
  
  private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger("8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f", 16);
  
  private static final int MAX_SMALL = BigInteger.valueOf(743L).bitLength();
  
  public static BigInteger createRandomPrime(int paramInt1, int paramInt2, SecureRandom paramSecureRandom) {
    BigInteger bigInteger;
    if (paramInt1 < 2)
      throw new IllegalArgumentException("bitLength < 2"); 
    if (paramInt1 == 2)
      return (paramSecureRandom.nextInt() < 0) ? TWO : THREE; 
    do {
      byte[] arrayOfByte = createRandom(paramInt1, paramSecureRandom);
      int i = 8 * arrayOfByte.length - paramInt1;
      byte b = (byte)(1 << 7 - i);
      arrayOfByte[0] = (byte)(arrayOfByte[0] | b);
      arrayOfByte[arrayOfByte.length - 1] = (byte)(arrayOfByte[arrayOfByte.length - 1] | 0x1);
      bigInteger = new BigInteger(1, arrayOfByte);
      if (paramInt1 <= MAX_SMALL)
        continue; 
      while (!bigInteger.gcd(SMALL_PRIMES_PRODUCT).equals(ONE))
        bigInteger = bigInteger.add(TWO); 
    } while (!bigInteger.isProbablePrime(paramInt2));
    return bigInteger;
  }
  
  private static byte[] createRandom(int paramInt, SecureRandom paramSecureRandom) throws IllegalArgumentException {
    if (paramInt < 1)
      throw new IllegalArgumentException("bitLength must be at least 1"); 
    int i = (paramInt + 7) / 8;
    byte[] arrayOfByte = new byte[i];
    paramSecureRandom.nextBytes(arrayOfByte);
    int j = 8 * i - paramInt;
    arrayOfByte[0] = (byte)(arrayOfByte[0] & (byte)(255 >>> j));
    return arrayOfByte;
  }
}
