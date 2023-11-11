package META-INF.versions.9.org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat192;

public class SecT163Field {
  private static final long M35 = 34359738367L;
  
  private static final long M55 = 36028797018963967L;
  
  private static final long[] ROOT_Z = new long[] { -5270498306774157648L, 5270498306774195053L, 19634136210L };
  
  public static void add(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    paramArrayOflong3[0] = paramArrayOflong1[0] ^ paramArrayOflong2[0];
    paramArrayOflong3[1] = paramArrayOflong1[1] ^ paramArrayOflong2[1];
    paramArrayOflong3[2] = paramArrayOflong1[2] ^ paramArrayOflong2[2];
  }
  
  public static void addExt(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    paramArrayOflong3[0] = paramArrayOflong1[0] ^ paramArrayOflong2[0];
    paramArrayOflong3[1] = paramArrayOflong1[1] ^ paramArrayOflong2[1];
    paramArrayOflong3[2] = paramArrayOflong1[2] ^ paramArrayOflong2[2];
    paramArrayOflong3[3] = paramArrayOflong1[3] ^ paramArrayOflong2[3];
    paramArrayOflong3[4] = paramArrayOflong1[4] ^ paramArrayOflong2[4];
    paramArrayOflong3[5] = paramArrayOflong1[5] ^ paramArrayOflong2[5];
  }
  
  public static void addOne(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong1[0] ^ 0x1L;
    paramArrayOflong2[1] = paramArrayOflong1[1];
    paramArrayOflong2[2] = paramArrayOflong1[2];
  }
  
  private static void addTo(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong2[0] ^ paramArrayOflong1[0];
    paramArrayOflong2[1] = paramArrayOflong2[1] ^ paramArrayOflong1[1];
    paramArrayOflong2[2] = paramArrayOflong2[2] ^ paramArrayOflong1[2];
  }
  
  public static long[] fromBigInteger(BigInteger paramBigInteger) {
    return Nat.fromBigInteger64(163, paramBigInteger);
  }
  
  public static void halfTrace(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = Nat192.createExt64();
    Nat192.copy64(paramArrayOflong1, paramArrayOflong2);
    for (byte b = 1; b < '£'; b += 2) {
      implSquare(paramArrayOflong2, arrayOfLong);
      reduce(arrayOfLong, paramArrayOflong2);
      implSquare(paramArrayOflong2, arrayOfLong);
      reduce(arrayOfLong, paramArrayOflong2);
      addTo(paramArrayOflong1, paramArrayOflong2);
    } 
  }
  
  public static void invert(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    if (Nat192.isZero64(paramArrayOflong1))
      throw new IllegalStateException(); 
    long[] arrayOfLong1 = Nat192.create64();
    long[] arrayOfLong2 = Nat192.create64();
    square(paramArrayOflong1, arrayOfLong1);
    squareN(arrayOfLong1, 1, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong2, 1, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong1, 3, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong2, 3, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong1, 9, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong2, 9, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong1, 27, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong2, 27, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, arrayOfLong1);
    squareN(arrayOfLong1, 81, arrayOfLong2);
    multiply(arrayOfLong1, arrayOfLong2, paramArrayOflong2);
  }
  
  public static void multiply(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    long[] arrayOfLong = new long[8];
    implMultiply(paramArrayOflong1, paramArrayOflong2, arrayOfLong);
    reduce(arrayOfLong, paramArrayOflong3);
  }
  
  public static void multiplyAddToExt(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    long[] arrayOfLong = new long[8];
    implMultiply(paramArrayOflong1, paramArrayOflong2, arrayOfLong);
    addExt(paramArrayOflong3, arrayOfLong, paramArrayOflong3);
  }
  
  public static void reduce(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0], l2 = paramArrayOflong1[1], l3 = paramArrayOflong1[2], l4 = paramArrayOflong1[3], l5 = paramArrayOflong1[4], l6 = paramArrayOflong1[5];
    l3 ^= l6 << 29L ^ l6 << 32L ^ l6 << 35L ^ l6 << 36L;
    l4 ^= l6 >>> 35L ^ l6 >>> 32L ^ l6 >>> 29L ^ l6 >>> 28L;
    l2 ^= l5 << 29L ^ l5 << 32L ^ l5 << 35L ^ l5 << 36L;
    l3 ^= l5 >>> 35L ^ l5 >>> 32L ^ l5 >>> 29L ^ l5 >>> 28L;
    l1 ^= l4 << 29L ^ l4 << 32L ^ l4 << 35L ^ l4 << 36L;
    l2 ^= l4 >>> 35L ^ l4 >>> 32L ^ l4 >>> 29L ^ l4 >>> 28L;
    long l7 = l3 >>> 35L;
    paramArrayOflong2[0] = l1 ^ l7 ^ l7 << 3L ^ l7 << 6L ^ l7 << 7L;
    paramArrayOflong2[1] = l2;
    paramArrayOflong2[2] = l3 & 0x7FFFFFFFFL;
  }
  
  public static void reduce29(long[] paramArrayOflong, int paramInt) {
    long l1 = paramArrayOflong[paramInt + 2], l2 = l1 >>> 35L;
    paramArrayOflong[paramInt] = paramArrayOflong[paramInt] ^ l2 ^ l2 << 3L ^ l2 << 6L ^ l2 << 7L;
    paramArrayOflong[paramInt + 2] = l1 & 0x7FFFFFFFFL;
  }
  
  public static void sqrt(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = Nat192.create64();
    long l1 = Interleave.unshuffle(paramArrayOflong1[0]), l2 = Interleave.unshuffle(paramArrayOflong1[1]);
    long l3 = l1 & 0xFFFFFFFFL | l2 << 32L;
    arrayOfLong[0] = l1 >>> 32L | l2 & 0xFFFFFFFF00000000L;
    l1 = Interleave.unshuffle(paramArrayOflong1[2]);
    long l4 = l1 & 0xFFFFFFFFL;
    arrayOfLong[1] = l1 >>> 32L;
    multiply(arrayOfLong, ROOT_Z, paramArrayOflong2);
    paramArrayOflong2[0] = paramArrayOflong2[0] ^ l3;
    paramArrayOflong2[1] = paramArrayOflong2[1] ^ l4;
  }
  
  public static void square(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = Nat192.createExt64();
    implSquare(paramArrayOflong1, arrayOfLong);
    reduce(arrayOfLong, paramArrayOflong2);
  }
  
  public static void squareAddToExt(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = Nat192.createExt64();
    implSquare(paramArrayOflong1, arrayOfLong);
    addExt(paramArrayOflong2, arrayOfLong, paramArrayOflong2);
  }
  
  public static void squareN(long[] paramArrayOflong1, int paramInt, long[] paramArrayOflong2) {
    long[] arrayOfLong = Nat192.createExt64();
    implSquare(paramArrayOflong1, arrayOfLong);
    reduce(arrayOfLong, paramArrayOflong2);
    while (--paramInt > 0) {
      implSquare(paramArrayOflong2, arrayOfLong);
      reduce(arrayOfLong, paramArrayOflong2);
    } 
  }
  
  public static int trace(long[] paramArrayOflong) {
    return (int)(paramArrayOflong[0] ^ paramArrayOflong[2] >>> 29L) & 0x1;
  }
  
  protected static void implCompactExt(long[] paramArrayOflong) {
    long l1 = paramArrayOflong[0], l2 = paramArrayOflong[1], l3 = paramArrayOflong[2], l4 = paramArrayOflong[3], l5 = paramArrayOflong[4], l6 = paramArrayOflong[5];
    paramArrayOflong[0] = l1 ^ l2 << 55L;
    paramArrayOflong[1] = l2 >>> 9L ^ l3 << 46L;
    paramArrayOflong[2] = l3 >>> 18L ^ l4 << 37L;
    paramArrayOflong[3] = l4 >>> 27L ^ l5 << 28L;
    paramArrayOflong[4] = l5 >>> 36L ^ l6 << 19L;
    paramArrayOflong[5] = l6 >>> 45L;
  }
  
  protected static void implMultiply(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    long l1 = paramArrayOflong1[0], l2 = paramArrayOflong1[1], l3 = paramArrayOflong1[2];
    l3 = l2 >>> 46L ^ l3 << 18L;
    l2 = (l1 >>> 55L ^ l2 << 9L) & 0x7FFFFFFFFFFFFFL;
    l1 &= 0x7FFFFFFFFFFFFFL;
    long l4 = paramArrayOflong2[0], l5 = paramArrayOflong2[1], l6 = paramArrayOflong2[2];
    l6 = l5 >>> 46L ^ l6 << 18L;
    l5 = (l4 >>> 55L ^ l5 << 9L) & 0x7FFFFFFFFFFFFFL;
    l4 &= 0x7FFFFFFFFFFFFFL;
    long[] arrayOfLong1 = paramArrayOflong3;
    long[] arrayOfLong2 = new long[10];
    implMulw(arrayOfLong1, l1, l4, arrayOfLong2, 0);
    implMulw(arrayOfLong1, l3, l6, arrayOfLong2, 2);
    long l7 = l1 ^ l2 ^ l3;
    long l8 = l4 ^ l5 ^ l6;
    implMulw(arrayOfLong1, l7, l8, arrayOfLong2, 4);
    long l9 = l2 << 1L ^ l3 << 2L;
    long l10 = l5 << 1L ^ l6 << 2L;
    implMulw(arrayOfLong1, l1 ^ l9, l4 ^ l10, arrayOfLong2, 6);
    implMulw(arrayOfLong1, l7 ^ l9, l8 ^ l10, arrayOfLong2, 8);
    long l11 = arrayOfLong2[6] ^ arrayOfLong2[8];
    long l12 = arrayOfLong2[7] ^ arrayOfLong2[9];
    long l13 = l11 << 1L ^ arrayOfLong2[6];
    long l14 = l11 ^ l12 << 1L ^ arrayOfLong2[7];
    long l15 = l12;
    long l16 = arrayOfLong2[0];
    long l17 = arrayOfLong2[1] ^ arrayOfLong2[0] ^ arrayOfLong2[4];
    long l18 = arrayOfLong2[1] ^ arrayOfLong2[5];
    long l19 = l16 ^ l13 ^ arrayOfLong2[2] << 4L ^ arrayOfLong2[2] << 1L;
    long l20 = l17 ^ l14 ^ arrayOfLong2[3] << 4L ^ arrayOfLong2[3] << 1L;
    long l21 = l18 ^ l15;
    l20 ^= l19 >>> 55L;
    l19 &= 0x7FFFFFFFFFFFFFL;
    l21 ^= l20 >>> 55L;
    l20 &= 0x7FFFFFFFFFFFFFL;
    l19 = l19 >>> 1L ^ (l20 & 0x1L) << 54L;
    l20 = l20 >>> 1L ^ (l21 & 0x1L) << 54L;
    l21 >>>= 1L;
    l19 ^= l19 << 1L;
    l19 ^= l19 << 2L;
    l19 ^= l19 << 4L;
    l19 ^= l19 << 8L;
    l19 ^= l19 << 16L;
    l19 ^= l19 << 32L;
    l19 &= 0x7FFFFFFFFFFFFFL;
    l20 ^= l19 >>> 54L;
    l20 ^= l20 << 1L;
    l20 ^= l20 << 2L;
    l20 ^= l20 << 4L;
    l20 ^= l20 << 8L;
    l20 ^= l20 << 16L;
    l20 ^= l20 << 32L;
    l20 &= 0x7FFFFFFFFFFFFFL;
    l21 ^= l20 >>> 54L;
    l21 ^= l21 << 1L;
    l21 ^= l21 << 2L;
    l21 ^= l21 << 4L;
    l21 ^= l21 << 8L;
    l21 ^= l21 << 16L;
    l21 ^= l21 << 32L;
    paramArrayOflong3[0] = l16;
    paramArrayOflong3[1] = l17 ^ l19 ^ arrayOfLong2[2];
    paramArrayOflong3[2] = l18 ^ l20 ^ l19 ^ arrayOfLong2[3];
    paramArrayOflong3[3] = l21 ^ l20;
    paramArrayOflong3[4] = l21 ^ arrayOfLong2[2];
    paramArrayOflong3[5] = arrayOfLong2[3];
    implCompactExt(paramArrayOflong3);
  }
  
  protected static void implMulw(long[] paramArrayOflong1, long paramLong1, long paramLong2, long[] paramArrayOflong2, int paramInt) {
    paramArrayOflong1[1] = paramLong2;
    paramArrayOflong1[2] = paramArrayOflong1[1] << 1L;
    paramArrayOflong1[3] = paramArrayOflong1[2] ^ paramLong2;
    paramArrayOflong1[4] = paramArrayOflong1[2] << 1L;
    paramArrayOflong1[5] = paramArrayOflong1[4] ^ paramLong2;
    paramArrayOflong1[6] = paramArrayOflong1[3] << 1L;
    paramArrayOflong1[7] = paramArrayOflong1[6] ^ paramLong2;
    int i = (int)paramLong1;
    long l1 = 0L, l2 = paramArrayOflong1[i & 0x3];
    byte b = 47;
    do {
      i = (int)(paramLong1 >>> b);
      long l = paramArrayOflong1[i & 0x7] ^ paramArrayOflong1[i >>> 3 & 0x7] << 3L ^ paramArrayOflong1[i >>> 6 & 0x7] << 6L;
      l2 ^= l << b;
      l1 ^= l >>> -b;
      b -= 9;
    } while (b > 0);
    paramArrayOflong2[paramInt] = l2 & 0x7FFFFFFFFFFFFFL;
    paramArrayOflong2[paramInt + 1] = l2 >>> 55L ^ l1 << 9L;
  }
  
  protected static void implSquare(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    Interleave.expand64To128(paramArrayOflong1, 0, 3, paramArrayOflong2, 0);
  }
}
