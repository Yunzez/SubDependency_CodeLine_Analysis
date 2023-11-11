package org.bouncycastle.crypto.modes.kgcm;

import org.bouncycastle.math.raw.Interleave;

public class KGCMUtil_256 {
  public static final int SIZE = 4;
  
  public static void add(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    paramArrayOflong3[0] = paramArrayOflong1[0] ^ paramArrayOflong2[0];
    paramArrayOflong3[1] = paramArrayOflong1[1] ^ paramArrayOflong2[1];
    paramArrayOflong3[2] = paramArrayOflong1[2] ^ paramArrayOflong2[2];
    paramArrayOflong3[3] = paramArrayOflong1[3] ^ paramArrayOflong2[3];
  }
  
  public static void copy(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong1[0];
    paramArrayOflong2[1] = paramArrayOflong1[1];
    paramArrayOflong2[2] = paramArrayOflong1[2];
    paramArrayOflong2[3] = paramArrayOflong1[3];
  }
  
  public static boolean equal(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l = 0L;
    l |= paramArrayOflong1[0] ^ paramArrayOflong2[0];
    l |= paramArrayOflong1[1] ^ paramArrayOflong2[1];
    l |= paramArrayOflong1[2] ^ paramArrayOflong2[2];
    l |= paramArrayOflong1[3] ^ paramArrayOflong2[3];
    return (l == 0L);
  }
  
  public static void multiply(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = paramArrayOflong1[2];
    long l4 = paramArrayOflong1[3];
    long l5 = paramArrayOflong2[0];
    long l6 = paramArrayOflong2[1];
    long l7 = paramArrayOflong2[2];
    long l8 = paramArrayOflong2[3];
    long l9 = 0L;
    long l10 = 0L;
    long l11 = 0L;
    long l12 = 0L;
    long l13 = 0L;
    for (byte b1 = 0; b1 < 64; b1++) {
      long l15 = -(l1 & 0x1L);
      l1 >>>= 1L;
      l9 ^= l5 & l15;
      l10 ^= l6 & l15;
      l11 ^= l7 & l15;
      l12 ^= l8 & l15;
      long l16 = -(l2 & 0x1L);
      l2 >>>= 1L;
      l10 ^= l5 & l16;
      l11 ^= l6 & l16;
      l12 ^= l7 & l16;
      l13 ^= l8 & l16;
      long l17 = l8 >> 63L;
      l8 = l8 << 1L | l7 >>> 63L;
      l7 = l7 << 1L | l6 >>> 63L;
      l6 = l6 << 1L | l5 >>> 63L;
      l5 = l5 << 1L ^ l17 & 0x425L;
    } 
    long l14 = l8;
    l8 = l7;
    l7 = l6;
    l6 = l5 ^ l14 >>> 62L ^ l14 >>> 59L ^ l14 >>> 54L;
    l5 = l14 ^ l14 << 2L ^ l14 << 5L ^ l14 << 10L;
    for (byte b2 = 0; b2 < 64; b2++) {
      long l15 = -(l3 & 0x1L);
      l3 >>>= 1L;
      l9 ^= l5 & l15;
      l10 ^= l6 & l15;
      l11 ^= l7 & l15;
      l12 ^= l8 & l15;
      long l16 = -(l4 & 0x1L);
      l4 >>>= 1L;
      l10 ^= l5 & l16;
      l11 ^= l6 & l16;
      l12 ^= l7 & l16;
      l13 ^= l8 & l16;
      long l17 = l8 >> 63L;
      l8 = l8 << 1L | l7 >>> 63L;
      l7 = l7 << 1L | l6 >>> 63L;
      l6 = l6 << 1L | l5 >>> 63L;
      l5 = l5 << 1L ^ l17 & 0x425L;
    } 
    l9 ^= l13 ^ l13 << 2L ^ l13 << 5L ^ l13 << 10L;
    l10 ^= l13 >>> 62L ^ l13 >>> 59L ^ l13 >>> 54L;
    paramArrayOflong3[0] = l9;
    paramArrayOflong3[1] = l10;
    paramArrayOflong3[2] = l11;
    paramArrayOflong3[3] = l12;
  }
  
  public static void multiplyX(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = paramArrayOflong1[2];
    long l4 = paramArrayOflong1[3];
    long l5 = l4 >> 63L;
    paramArrayOflong2[0] = l1 << 1L ^ l5 & 0x425L;
    paramArrayOflong2[1] = l2 << 1L | l1 >>> 63L;
    paramArrayOflong2[2] = l3 << 1L | l2 >>> 63L;
    paramArrayOflong2[3] = l4 << 1L | l3 >>> 63L;
  }
  
  public static void multiplyX8(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = paramArrayOflong1[2];
    long l4 = paramArrayOflong1[3];
    long l5 = l4 >>> 56L;
    paramArrayOflong2[0] = l1 << 8L ^ l5 ^ l5 << 2L ^ l5 << 5L ^ l5 << 10L;
    paramArrayOflong2[1] = l2 << 8L | l1 >>> 56L;
    paramArrayOflong2[2] = l3 << 8L | l2 >>> 56L;
    paramArrayOflong2[3] = l4 << 8L | l3 >>> 56L;
  }
  
  public static void one(long[] paramArrayOflong) {
    paramArrayOflong[0] = 1L;
    paramArrayOflong[1] = 0L;
    paramArrayOflong[2] = 0L;
    paramArrayOflong[3] = 0L;
  }
  
  public static void square(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = new long[8];
    byte b;
    for (b = 0; b < 4; b++)
      Interleave.expand64To128(paramArrayOflong1[b], arrayOfLong, b << 1); 
    b = 8;
    while (--b >= 4) {
      long l = arrayOfLong[b];
      arrayOfLong[b - 4] = arrayOfLong[b - 4] ^ l ^ l << 2L ^ l << 5L ^ l << 10L;
      arrayOfLong[b - 4 + 1] = arrayOfLong[b - 4 + 1] ^ l >>> 62L ^ l >>> 59L ^ l >>> 54L;
    } 
    copy(arrayOfLong, paramArrayOflong2);
  }
  
  public static void x(long[] paramArrayOflong) {
    paramArrayOflong[0] = 2L;
    paramArrayOflong[1] = 0L;
    paramArrayOflong[2] = 0L;
    paramArrayOflong[3] = 0L;
  }
  
  public static void zero(long[] paramArrayOflong) {
    paramArrayOflong[0] = 0L;
    paramArrayOflong[1] = 0L;
    paramArrayOflong[2] = 0L;
    paramArrayOflong[3] = 0L;
  }
}
