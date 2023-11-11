package org.bouncycastle.crypto.modes.kgcm;

import org.bouncycastle.math.raw.Interleave;

public class KGCMUtil_512 {
  public static final int SIZE = 8;
  
  public static void add(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    paramArrayOflong3[0] = paramArrayOflong1[0] ^ paramArrayOflong2[0];
    paramArrayOflong3[1] = paramArrayOflong1[1] ^ paramArrayOflong2[1];
    paramArrayOflong3[2] = paramArrayOflong1[2] ^ paramArrayOflong2[2];
    paramArrayOflong3[3] = paramArrayOflong1[3] ^ paramArrayOflong2[3];
    paramArrayOflong3[4] = paramArrayOflong1[4] ^ paramArrayOflong2[4];
    paramArrayOflong3[5] = paramArrayOflong1[5] ^ paramArrayOflong2[5];
    paramArrayOflong3[6] = paramArrayOflong1[6] ^ paramArrayOflong2[6];
    paramArrayOflong3[7] = paramArrayOflong1[7] ^ paramArrayOflong2[7];
  }
  
  public static void copy(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong1[0];
    paramArrayOflong2[1] = paramArrayOflong1[1];
    paramArrayOflong2[2] = paramArrayOflong1[2];
    paramArrayOflong2[3] = paramArrayOflong1[3];
    paramArrayOflong2[4] = paramArrayOflong1[4];
    paramArrayOflong2[5] = paramArrayOflong1[5];
    paramArrayOflong2[6] = paramArrayOflong1[6];
    paramArrayOflong2[7] = paramArrayOflong1[7];
  }
  
  public static boolean equal(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l = 0L;
    l |= paramArrayOflong1[0] ^ paramArrayOflong2[0];
    l |= paramArrayOflong1[1] ^ paramArrayOflong2[1];
    l |= paramArrayOflong1[2] ^ paramArrayOflong2[2];
    l |= paramArrayOflong1[3] ^ paramArrayOflong2[3];
    l |= paramArrayOflong1[4] ^ paramArrayOflong2[4];
    l |= paramArrayOflong1[5] ^ paramArrayOflong2[5];
    l |= paramArrayOflong1[6] ^ paramArrayOflong2[6];
    l |= paramArrayOflong1[7] ^ paramArrayOflong2[7];
    return (l == 0L);
  }
  
  public static void multiply(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    long l1 = paramArrayOflong2[0];
    long l2 = paramArrayOflong2[1];
    long l3 = paramArrayOflong2[2];
    long l4 = paramArrayOflong2[3];
    long l5 = paramArrayOflong2[4];
    long l6 = paramArrayOflong2[5];
    long l7 = paramArrayOflong2[6];
    long l8 = paramArrayOflong2[7];
    long l9 = 0L;
    long l10 = 0L;
    long l11 = 0L;
    long l12 = 0L;
    long l13 = 0L;
    long l14 = 0L;
    long l15 = 0L;
    long l16 = 0L;
    long l17 = 0L;
    for (byte b = 0; b < 8; b += 2) {
      long l18 = paramArrayOflong1[b];
      long l19 = paramArrayOflong1[b + 1];
      for (byte b1 = 0; b1 < 64; b1++) {
        long l21 = -(l18 & 0x1L);
        l18 >>>= 1L;
        l9 ^= l1 & l21;
        l10 ^= l2 & l21;
        l11 ^= l3 & l21;
        l12 ^= l4 & l21;
        l13 ^= l5 & l21;
        l14 ^= l6 & l21;
        l15 ^= l7 & l21;
        l16 ^= l8 & l21;
        long l22 = -(l19 & 0x1L);
        l19 >>>= 1L;
        l10 ^= l1 & l22;
        l11 ^= l2 & l22;
        l12 ^= l3 & l22;
        l13 ^= l4 & l22;
        l14 ^= l5 & l22;
        l15 ^= l6 & l22;
        l16 ^= l7 & l22;
        l17 ^= l8 & l22;
        long l23 = l8 >> 63L;
        l8 = l8 << 1L | l7 >>> 63L;
        l7 = l7 << 1L | l6 >>> 63L;
        l6 = l6 << 1L | l5 >>> 63L;
        l5 = l5 << 1L | l4 >>> 63L;
        l4 = l4 << 1L | l3 >>> 63L;
        l3 = l3 << 1L | l2 >>> 63L;
        l2 = l2 << 1L | l1 >>> 63L;
        l1 = l1 << 1L ^ l23 & 0x125L;
      } 
      long l20 = l8;
      l8 = l7;
      l7 = l6;
      l6 = l5;
      l5 = l4;
      l4 = l3;
      l3 = l2;
      l2 = l1 ^ l20 >>> 62L ^ l20 >>> 59L ^ l20 >>> 56L;
      l1 = l20 ^ l20 << 2L ^ l20 << 5L ^ l20 << 8L;
    } 
    l9 ^= l17 ^ l17 << 2L ^ l17 << 5L ^ l17 << 8L;
    l10 ^= l17 >>> 62L ^ l17 >>> 59L ^ l17 >>> 56L;
    paramArrayOflong3[0] = l9;
    paramArrayOflong3[1] = l10;
    paramArrayOflong3[2] = l11;
    paramArrayOflong3[3] = l12;
    paramArrayOflong3[4] = l13;
    paramArrayOflong3[5] = l14;
    paramArrayOflong3[6] = l15;
    paramArrayOflong3[7] = l16;
  }
  
  public static void multiplyX(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = paramArrayOflong1[2];
    long l4 = paramArrayOflong1[3];
    long l5 = paramArrayOflong1[4];
    long l6 = paramArrayOflong1[5];
    long l7 = paramArrayOflong1[6];
    long l8 = paramArrayOflong1[7];
    long l9 = l8 >> 63L;
    paramArrayOflong2[0] = l1 << 1L ^ l9 & 0x125L;
    paramArrayOflong2[1] = l2 << 1L | l1 >>> 63L;
    paramArrayOflong2[2] = l3 << 1L | l2 >>> 63L;
    paramArrayOflong2[3] = l4 << 1L | l3 >>> 63L;
    paramArrayOflong2[4] = l5 << 1L | l4 >>> 63L;
    paramArrayOflong2[5] = l6 << 1L | l5 >>> 63L;
    paramArrayOflong2[6] = l7 << 1L | l6 >>> 63L;
    paramArrayOflong2[7] = l8 << 1L | l7 >>> 63L;
  }
  
  public static void multiplyX8(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = paramArrayOflong1[2];
    long l4 = paramArrayOflong1[3];
    long l5 = paramArrayOflong1[4];
    long l6 = paramArrayOflong1[5];
    long l7 = paramArrayOflong1[6];
    long l8 = paramArrayOflong1[7];
    long l9 = l8 >>> 56L;
    paramArrayOflong2[0] = l1 << 8L ^ l9 ^ l9 << 2L ^ l9 << 5L ^ l9 << 8L;
    paramArrayOflong2[1] = l2 << 8L | l1 >>> 56L;
    paramArrayOflong2[2] = l3 << 8L | l2 >>> 56L;
    paramArrayOflong2[3] = l4 << 8L | l3 >>> 56L;
    paramArrayOflong2[4] = l5 << 8L | l4 >>> 56L;
    paramArrayOflong2[5] = l6 << 8L | l5 >>> 56L;
    paramArrayOflong2[6] = l7 << 8L | l6 >>> 56L;
    paramArrayOflong2[7] = l8 << 8L | l7 >>> 56L;
  }
  
  public static void one(long[] paramArrayOflong) {
    paramArrayOflong[0] = 1L;
    paramArrayOflong[1] = 0L;
    paramArrayOflong[2] = 0L;
    paramArrayOflong[3] = 0L;
    paramArrayOflong[4] = 0L;
    paramArrayOflong[5] = 0L;
    paramArrayOflong[6] = 0L;
    paramArrayOflong[7] = 0L;
  }
  
  public static void square(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = new long[16];
    byte b;
    for (b = 0; b < 8; b++)
      Interleave.expand64To128(paramArrayOflong1[b], arrayOfLong, b << 1); 
    b = 16;
    while (--b >= 8) {
      long l = arrayOfLong[b];
      arrayOfLong[b - 8] = arrayOfLong[b - 8] ^ l ^ l << 2L ^ l << 5L ^ l << 8L;
      arrayOfLong[b - 8 + 1] = arrayOfLong[b - 8 + 1] ^ l >>> 62L ^ l >>> 59L ^ l >>> 56L;
    } 
    copy(arrayOfLong, paramArrayOflong2);
  }
  
  public static void x(long[] paramArrayOflong) {
    paramArrayOflong[0] = 2L;
    paramArrayOflong[1] = 0L;
    paramArrayOflong[2] = 0L;
    paramArrayOflong[3] = 0L;
    paramArrayOflong[4] = 0L;
    paramArrayOflong[5] = 0L;
    paramArrayOflong[6] = 0L;
    paramArrayOflong[7] = 0L;
  }
  
  public static void zero(long[] paramArrayOflong) {
    paramArrayOflong[0] = 0L;
    paramArrayOflong[1] = 0L;
    paramArrayOflong[2] = 0L;
    paramArrayOflong[3] = 0L;
    paramArrayOflong[4] = 0L;
    paramArrayOflong[5] = 0L;
    paramArrayOflong[6] = 0L;
    paramArrayOflong[7] = 0L;
  }
}
