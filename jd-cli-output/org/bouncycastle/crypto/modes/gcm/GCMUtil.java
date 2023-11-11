package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.util.Longs;
import org.bouncycastle.util.Pack;

public abstract class GCMUtil {
  public static final int SIZE_BYTES = 16;
  
  public static final int SIZE_INTS = 4;
  
  public static final int SIZE_LONGS = 2;
  
  private static final int E1 = -520093696;
  
  private static final long E1L = -2233785415175766016L;
  
  public static byte[] oneAsBytes() {
    byte[] arrayOfByte = new byte[16];
    arrayOfByte[0] = Byte.MIN_VALUE;
    return arrayOfByte;
  }
  
  public static int[] oneAsInts() {
    int[] arrayOfInt = new int[4];
    arrayOfInt[0] = Integer.MIN_VALUE;
    return arrayOfInt;
  }
  
  public static long[] oneAsLongs() {
    long[] arrayOfLong = new long[2];
    arrayOfLong[0] = Long.MIN_VALUE;
    return arrayOfLong;
  }
  
  public static byte areEqual(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    int i = 0;
    for (byte b = 0; b < 16; b++)
      i |= paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]; 
    i = i >>> 1 | i & 0x1;
    return (byte)(i - 1 >> 31);
  }
  
  public static int areEqual(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = 0;
    i |= paramArrayOfint1[0] ^ paramArrayOfint2[0];
    i |= paramArrayOfint1[1] ^ paramArrayOfint2[1];
    i |= paramArrayOfint1[2] ^ paramArrayOfint2[2];
    i |= paramArrayOfint1[3] ^ paramArrayOfint2[3];
    i = i >>> 1 | i & 0x1;
    return i - 1 >> 31;
  }
  
  public static long areEqual(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l = 0L;
    l |= paramArrayOflong1[0] ^ paramArrayOflong2[0];
    l |= paramArrayOflong1[1] ^ paramArrayOflong2[1];
    l = l >>> 1L | l & 0x1L;
    return l - 1L >> 63L;
  }
  
  public static byte[] asBytes(int[] paramArrayOfint) {
    byte[] arrayOfByte = new byte[16];
    Pack.intToBigEndian(paramArrayOfint, 0, 4, arrayOfByte, 0);
    return arrayOfByte;
  }
  
  public static void asBytes(int[] paramArrayOfint, byte[] paramArrayOfbyte) {
    Pack.intToBigEndian(paramArrayOfint, 0, 4, paramArrayOfbyte, 0);
  }
  
  public static byte[] asBytes(long[] paramArrayOflong) {
    byte[] arrayOfByte = new byte[16];
    Pack.longToBigEndian(paramArrayOflong, 0, 2, arrayOfByte, 0);
    return arrayOfByte;
  }
  
  public static void asBytes(long[] paramArrayOflong, byte[] paramArrayOfbyte) {
    Pack.longToBigEndian(paramArrayOflong, 0, 2, paramArrayOfbyte, 0);
  }
  
  public static int[] asInts(byte[] paramArrayOfbyte) {
    int[] arrayOfInt = new int[4];
    Pack.bigEndianToInt(paramArrayOfbyte, 0, arrayOfInt, 0, 4);
    return arrayOfInt;
  }
  
  public static void asInts(byte[] paramArrayOfbyte, int[] paramArrayOfint) {
    Pack.bigEndianToInt(paramArrayOfbyte, 0, paramArrayOfint, 0, 4);
  }
  
  public static long[] asLongs(byte[] paramArrayOfbyte) {
    long[] arrayOfLong = new long[2];
    Pack.bigEndianToLong(paramArrayOfbyte, 0, arrayOfLong, 0, 2);
    return arrayOfLong;
  }
  
  public static void asLongs(byte[] paramArrayOfbyte, long[] paramArrayOflong) {
    Pack.bigEndianToLong(paramArrayOfbyte, 0, paramArrayOflong, 0, 2);
  }
  
  public static void copy(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    for (byte b = 0; b < 16; b++)
      paramArrayOfbyte2[b] = paramArrayOfbyte1[b]; 
  }
  
  public static void copy(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    paramArrayOfint2[0] = paramArrayOfint1[0];
    paramArrayOfint2[1] = paramArrayOfint1[1];
    paramArrayOfint2[2] = paramArrayOfint1[2];
    paramArrayOfint2[3] = paramArrayOfint1[3];
  }
  
  public static void copy(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong1[0];
    paramArrayOflong2[1] = paramArrayOflong1[1];
  }
  
  public static void divideP(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l1 >> 63L;
    l1 ^= l3 & 0xE100000000000000L;
    paramArrayOflong2[0] = l1 << 1L | l2 >>> 63L;
    paramArrayOflong2[1] = l2 << 1L | -l3;
  }
  
  public static void multiply(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    long[] arrayOfLong1 = asLongs(paramArrayOfbyte1);
    long[] arrayOfLong2 = asLongs(paramArrayOfbyte2);
    multiply(arrayOfLong1, arrayOfLong2);
    asBytes(arrayOfLong1, paramArrayOfbyte1);
  }
  
  public static void multiply(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = paramArrayOfint2[0];
    int j = paramArrayOfint2[1];
    int k = paramArrayOfint2[2];
    int m = paramArrayOfint2[3];
    int n = 0;
    int i1 = 0;
    int i2 = 0;
    int i3 = 0;
    for (byte b = 0; b < 4; b++) {
      int i4 = paramArrayOfint1[b];
      for (byte b1 = 0; b1 < 32; b1++) {
        int i5 = i4 >> 31;
        i4 <<= 1;
        n ^= i & i5;
        i1 ^= j & i5;
        i2 ^= k & i5;
        i3 ^= m & i5;
        int i6 = m << 31 >> 8;
        m = m >>> 1 | k << 31;
        k = k >>> 1 | j << 31;
        j = j >>> 1 | i << 31;
        i = i >>> 1 ^ i6 & 0xE1000000;
      } 
    } 
    paramArrayOfint1[0] = n;
    paramArrayOfint1[1] = i1;
    paramArrayOfint1[2] = i2;
    paramArrayOfint1[3] = i3;
  }
  
  public static void multiply(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = paramArrayOflong2[0];
    long l4 = paramArrayOflong2[1];
    long l5 = Longs.reverse(l1);
    long l6 = Longs.reverse(l2);
    long l7 = Longs.reverse(l3);
    long l8 = Longs.reverse(l4);
    long l9 = Longs.reverse(implMul64(l5, l7));
    long l10 = implMul64(l1, l3) << 1L;
    long l11 = Longs.reverse(implMul64(l6, l8));
    long l12 = implMul64(l2, l4) << 1L;
    long l13 = Longs.reverse(implMul64(l5 ^ l6, l7 ^ l8));
    long l14 = implMul64(l1 ^ l2, l3 ^ l4) << 1L;
    long l15 = l9;
    long l16 = l10 ^ l9 ^ l11 ^ l13;
    long l17 = l11 ^ l10 ^ l12 ^ l14;
    long l18 = l12;
    l16 ^= l18 ^ l18 >>> 1L ^ l18 >>> 2L ^ l18 >>> 7L;
    l17 ^= l18 << 62L ^ l18 << 57L;
    l15 ^= l17 ^ l17 >>> 1L ^ l17 >>> 2L ^ l17 >>> 7L;
    l16 ^= l17 << 63L ^ l17 << 62L ^ l17 << 57L;
    paramArrayOflong1[0] = l15;
    paramArrayOflong1[1] = l16;
  }
  
  public static void multiplyP(int[] paramArrayOfint) {
    int i = paramArrayOfint[0];
    int j = paramArrayOfint[1];
    int k = paramArrayOfint[2];
    int m = paramArrayOfint[3];
    int n = m << 31 >> 31;
    paramArrayOfint[0] = i >>> 1 ^ n & 0xE1000000;
    paramArrayOfint[1] = j >>> 1 | i << 31;
    paramArrayOfint[2] = k >>> 1 | j << 31;
    paramArrayOfint[3] = m >>> 1 | k << 31;
  }
  
  public static void multiplyP(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = paramArrayOfint1[0];
    int j = paramArrayOfint1[1];
    int k = paramArrayOfint1[2];
    int m = paramArrayOfint1[3];
    int n = m << 31 >> 31;
    paramArrayOfint2[0] = i >>> 1 ^ n & 0xE1000000;
    paramArrayOfint2[1] = j >>> 1 | i << 31;
    paramArrayOfint2[2] = k >>> 1 | j << 31;
    paramArrayOfint2[3] = m >>> 1 | k << 31;
  }
  
  public static void multiplyP(long[] paramArrayOflong) {
    long l1 = paramArrayOflong[0];
    long l2 = paramArrayOflong[1];
    long l3 = l2 << 63L >> 63L;
    paramArrayOflong[0] = l1 >>> 1L ^ l3 & 0xE100000000000000L;
    paramArrayOflong[1] = l2 >>> 1L | l1 << 63L;
  }
  
  public static void multiplyP(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l2 << 63L >> 63L;
    paramArrayOflong2[0] = l1 >>> 1L ^ l3 & 0xE100000000000000L;
    paramArrayOflong2[1] = l2 >>> 1L | l1 << 63L;
  }
  
  public static void multiplyP3(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l2 << 61L;
    paramArrayOflong2[0] = l1 >>> 3L ^ l3 ^ l3 >>> 1L ^ l3 >>> 2L ^ l3 >>> 7L;
    paramArrayOflong2[1] = l2 >>> 3L | l1 << 61L;
  }
  
  public static void multiplyP4(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l2 << 60L;
    paramArrayOflong2[0] = l1 >>> 4L ^ l3 ^ l3 >>> 1L ^ l3 >>> 2L ^ l3 >>> 7L;
    paramArrayOflong2[1] = l2 >>> 4L | l1 << 60L;
  }
  
  public static void multiplyP7(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l2 << 57L;
    paramArrayOflong2[0] = l1 >>> 7L ^ l3 ^ l3 >>> 1L ^ l3 >>> 2L ^ l3 >>> 7L;
    paramArrayOflong2[1] = l2 >>> 7L | l1 << 57L;
  }
  
  public static void multiplyP8(int[] paramArrayOfint) {
    int i = paramArrayOfint[0];
    int j = paramArrayOfint[1];
    int k = paramArrayOfint[2];
    int m = paramArrayOfint[3];
    int n = m << 24;
    paramArrayOfint[0] = i >>> 8 ^ n ^ n >>> 1 ^ n >>> 2 ^ n >>> 7;
    paramArrayOfint[1] = j >>> 8 | i << 24;
    paramArrayOfint[2] = k >>> 8 | j << 24;
    paramArrayOfint[3] = m >>> 8 | k << 24;
  }
  
  public static void multiplyP8(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = paramArrayOfint1[0];
    int j = paramArrayOfint1[1];
    int k = paramArrayOfint1[2];
    int m = paramArrayOfint1[3];
    int n = m << 24;
    paramArrayOfint2[0] = i >>> 8 ^ n ^ n >>> 1 ^ n >>> 2 ^ n >>> 7;
    paramArrayOfint2[1] = j >>> 8 | i << 24;
    paramArrayOfint2[2] = k >>> 8 | j << 24;
    paramArrayOfint2[3] = m >>> 8 | k << 24;
  }
  
  public static void multiplyP8(long[] paramArrayOflong) {
    long l1 = paramArrayOflong[0];
    long l2 = paramArrayOflong[1];
    long l3 = l2 << 56L;
    paramArrayOflong[0] = l1 >>> 8L ^ l3 ^ l3 >>> 1L ^ l3 >>> 2L ^ l3 >>> 7L;
    paramArrayOflong[1] = l2 >>> 8L | l1 << 56L;
  }
  
  public static void multiplyP8(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long l1 = paramArrayOflong1[0];
    long l2 = paramArrayOflong1[1];
    long l3 = l2 << 56L;
    paramArrayOflong2[0] = l1 >>> 8L ^ l3 ^ l3 >>> 1L ^ l3 >>> 2L ^ l3 >>> 7L;
    paramArrayOflong2[1] = l2 >>> 8L | l1 << 56L;
  }
  
  public static long[] pAsLongs() {
    long[] arrayOfLong = new long[2];
    arrayOfLong[0] = 4611686018427387904L;
    return arrayOfLong;
  }
  
  public static void square(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    long[] arrayOfLong = new long[4];
    Interleave.expand64To128Rev(paramArrayOflong1[0], arrayOfLong, 0);
    Interleave.expand64To128Rev(paramArrayOflong1[1], arrayOfLong, 2);
    long l1 = arrayOfLong[0];
    long l2 = arrayOfLong[1];
    long l3 = arrayOfLong[2];
    long l4 = arrayOfLong[3];
    l2 ^= l4 ^ l4 >>> 1L ^ l4 >>> 2L ^ l4 >>> 7L;
    l3 ^= l4 << 63L ^ l4 << 62L ^ l4 << 57L;
    l1 ^= l3 ^ l3 >>> 1L ^ l3 >>> 2L ^ l3 >>> 7L;
    l2 ^= l3 << 63L ^ l3 << 62L ^ l3 << 57L;
    paramArrayOflong2[0] = l1;
    paramArrayOflong2[1] = l2;
  }
  
  public static void xor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte b = 0;
    do {
      paramArrayOfbyte1[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]);
      paramArrayOfbyte1[++b] = (byte)(paramArrayOfbyte1[++b] ^ paramArrayOfbyte2[b]);
      paramArrayOfbyte1[++b] = (byte)(paramArrayOfbyte1[++b] ^ paramArrayOfbyte2[b]);
      paramArrayOfbyte1[++b] = (byte)(paramArrayOfbyte1[++b] ^ paramArrayOfbyte2[b]);
    } while (++b < 16);
  }
  
  public static void xor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    byte b = 0;
    do {
      paramArrayOfbyte1[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[paramInt + b]);
      paramArrayOfbyte1[++b] = (byte)(paramArrayOfbyte1[++b] ^ paramArrayOfbyte2[paramInt + b]);
      paramArrayOfbyte1[++b] = (byte)(paramArrayOfbyte1[++b] ^ paramArrayOfbyte2[paramInt + b]);
      paramArrayOfbyte1[++b] = (byte)(paramArrayOfbyte1[++b] ^ paramArrayOfbyte2[paramInt + b]);
    } while (++b < 16);
  }
  
  public static void xor(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, int paramInt3) {
    byte b = 0;
    do {
      paramArrayOfbyte3[paramInt3 + b] = (byte)(paramArrayOfbyte1[paramInt1 + b] ^ paramArrayOfbyte2[paramInt2 + b]);
      paramArrayOfbyte3[paramInt3 + ++b] = (byte)(paramArrayOfbyte1[paramInt1 + b] ^ paramArrayOfbyte2[paramInt2 + b]);
      paramArrayOfbyte3[paramInt3 + ++b] = (byte)(paramArrayOfbyte1[paramInt1 + b] ^ paramArrayOfbyte2[paramInt2 + b]);
      paramArrayOfbyte3[paramInt3 + ++b] = (byte)(paramArrayOfbyte1[paramInt1 + b] ^ paramArrayOfbyte2[paramInt2 + b]);
    } while (++b < 16);
  }
  
  public static void xor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2) {
    while (--paramInt2 >= 0)
      paramArrayOfbyte1[paramInt2] = (byte)(paramArrayOfbyte1[paramInt2] ^ paramArrayOfbyte2[paramInt1 + paramInt2]); 
  }
  
  public static void xor(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, int paramInt3) {
    while (--paramInt3 >= 0)
      paramArrayOfbyte1[paramInt1 + paramInt3] = (byte)(paramArrayOfbyte1[paramInt1 + paramInt3] ^ paramArrayOfbyte2[paramInt2 + paramInt3]); 
  }
  
  public static void xor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    byte b = 0;
    do {
      paramArrayOfbyte3[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]);
      paramArrayOfbyte3[++b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]);
      paramArrayOfbyte3[++b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]);
      paramArrayOfbyte3[++b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]);
    } while (++b < 16);
  }
  
  public static void xor(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    paramArrayOfint1[0] = paramArrayOfint1[0] ^ paramArrayOfint2[0];
    paramArrayOfint1[1] = paramArrayOfint1[1] ^ paramArrayOfint2[1];
    paramArrayOfint1[2] = paramArrayOfint1[2] ^ paramArrayOfint2[2];
    paramArrayOfint1[3] = paramArrayOfint1[3] ^ paramArrayOfint2[3];
  }
  
  public static void xor(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    paramArrayOfint3[0] = paramArrayOfint1[0] ^ paramArrayOfint2[0];
    paramArrayOfint3[1] = paramArrayOfint1[1] ^ paramArrayOfint2[1];
    paramArrayOfint3[2] = paramArrayOfint1[2] ^ paramArrayOfint2[2];
    paramArrayOfint3[3] = paramArrayOfint1[3] ^ paramArrayOfint2[3];
  }
  
  public static void xor(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong1[0] = paramArrayOflong1[0] ^ paramArrayOflong2[0];
    paramArrayOflong1[1] = paramArrayOflong1[1] ^ paramArrayOflong2[1];
  }
  
  public static void xor(long[] paramArrayOflong1, long[] paramArrayOflong2, long[] paramArrayOflong3) {
    paramArrayOflong3[0] = paramArrayOflong1[0] ^ paramArrayOflong2[0];
    paramArrayOflong3[1] = paramArrayOflong1[1] ^ paramArrayOflong2[1];
  }
  
  private static long implMul64(long paramLong1, long paramLong2) {
    long l1 = paramLong1 & 0x1111111111111111L;
    long l2 = paramLong1 & 0x2222222222222222L;
    long l3 = paramLong1 & 0x4444444444444444L;
    long l4 = paramLong1 & 0x8888888888888888L;
    long l5 = paramLong2 & 0x1111111111111111L;
    long l6 = paramLong2 & 0x2222222222222222L;
    long l7 = paramLong2 & 0x4444444444444444L;
    long l8 = paramLong2 & 0x8888888888888888L;
    long l9 = l1 * l5 ^ l2 * l8 ^ l3 * l7 ^ l4 * l6;
    long l10 = l1 * l6 ^ l2 * l5 ^ l3 * l8 ^ l4 * l7;
    long l11 = l1 * l7 ^ l2 * l6 ^ l3 * l5 ^ l4 * l8;
    long l12 = l1 * l8 ^ l2 * l7 ^ l3 * l6 ^ l4 * l5;
    l9 &= 0x1111111111111111L;
    l10 &= 0x2222222222222222L;
    l11 &= 0x4444444444444444L;
    l12 &= 0x8888888888888888L;
    return l9 | l10 | l11 | l12;
  }
}
