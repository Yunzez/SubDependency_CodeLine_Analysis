package org.bouncycastle.crypto.modes.kgcm;

import org.bouncycastle.math.raw.Interleave;

public class KGCMUtil_128 {
  public static final int SIZE = 2;
  
  public static void add(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    paramArrayOflong3[0] = paramArrayOflong1[0] ^ paramArrayOflong2[0];
    paramArrayOflong3[1] = paramArrayOflong1[1] ^ paramArrayOflong2[1];
  }
  
  public static void copy(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong1[0];
    paramArrayOflong2[1] = paramArrayOflong1[1];
  }
  
  public static boolean equal(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l = 0L;
    l |= paramArrayOflong1[0] ^ paramArrayOflong2[0];
    l |= paramArrayOflong1[1] ^ paramArrayOflong2[1];
    return (l == 0L);
  }
  
  public static void multiply(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = paramArrayOflong2[0];
    long l4 = paramArrayOflong2[1];
    long l5 = 0L;
    long l6 = 0L;
    long l7 = 0L;
    for (byte b = 0; b < 64; b++) {
      long l8 = -(l1 & 0x1L);
      l1 >>>= 1L;
      l5 ^= l3 & l8;
      l6 ^= l4 & l8;
      long l9 = -(l2 & 0x1L);
      l2 >>>= 1L;
      l6 ^= l3 & l9;
      l7 ^= l4 & l9;
      long l10 = l4 >> 63L;
      l4 = l4 << 1L | l3 >>> 63L;
      l3 = l3 << 1L ^ l10 & 0x87L;
    } 
    l5 ^= l7 ^ l7 << 1L ^ l7 << 2L ^ l7 << 7L;
    l6 ^= l7 >>> 63L ^ l7 >>> 62L ^ l7 >>> 57L;
    paramArrayOflong3[0] = l5;
    paramArrayOflong3[1] = l6;
  }
  
  public static void multiplyX(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l2 >> 63L;
    paramArrayOflong2[0] = l1 << 1L ^ l3 & 0x87L;
    paramArrayOflong2[1] = l2 << 1L | l1 >>> 63L;
  }
  
  public static void multiplyX8(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l2 >>> 56L;
    paramArrayOflong2[0] = l1 << 8L ^ l3 ^ l3 << 1L ^ l3 << 2L ^ l3 << 7L;
    paramArrayOflong2[1] = l2 << 8L | l1 >>> 56L;
  }
  
  public static void one(long[] paramArrayOflong) {
    paramArrayOflong[0] = 1L;
    paramArrayOflong[1] = 0L;
  }
  
  public static void square(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = new long[4];
    Interleave.expand64To128(paramArrayOflong1[0], arrayOfLong, 0);
    Interleave.expand64To128(paramArrayOflong1[1], arrayOfLong, 2);
    long l1 = arrayOfLong[0];
    long l2 = arrayOfLong[1];
    long l3 = arrayOfLong[2];
    long l4 = arrayOfLong[3];
    l2 ^= l4 ^ l4 << 1L ^ l4 << 2L ^ l4 << 7L;
    l3 ^= l4 >>> 63L ^ l4 >>> 62L ^ l4 >>> 57L;
    l1 ^= l3 ^ l3 << 1L ^ l3 << 2L ^ l3 << 7L;
    l2 ^= l3 >>> 63L ^ l3 >>> 62L ^ l3 >>> 57L;
    paramArrayOflong2[0] = l1;
    paramArrayOflong2[1] = l2;
  }
  
  public static void x(long[] paramArrayOflong) {
    paramArrayOflong[0] = 2L;
    paramArrayOflong[1] = 0L;
  }
  
  public static void zero(long[] paramArrayOflong) {
    paramArrayOflong[0] = 0L;
    paramArrayOflong[1] = 0L;
  }
}
