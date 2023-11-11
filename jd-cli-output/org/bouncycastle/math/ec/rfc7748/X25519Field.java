package org.bouncycastle.math.ec.rfc7748;

import org.bouncycastle.math.raw.Mod;

public abstract class X25519Field {
  public static final int SIZE = 10;
  
  private static final int M24 = 16777215;
  
  private static final int M25 = 33554431;
  
  private static final int M26 = 67108863;
  
  private static final int[] P32 = new int[] { -19, -1, -1, -1, -1, -1, -1, Integer.MAX_VALUE };
  
  private static final int[] ROOT_NEG_ONE = new int[] { 34513072, 59165138, 4688974, 3500415, 6194736, 33281959, 54535759, 32551604, 163342, 5703241 };
  
  public static void add(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    for (byte b = 0; b < 10; b++)
      paramArrayOfint3[b] = paramArrayOfint1[b] + paramArrayOfint2[b]; 
  }
  
  public static void addOne(int[] paramArrayOfint) {
    paramArrayOfint[0] = paramArrayOfint[0] + 1;
  }
  
  public static void addOne(int[] paramArrayOfint, int paramInt) {
    paramArrayOfint[paramInt] = paramArrayOfint[paramInt] + 1;
  }
  
  public static void apm(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3, int[] paramArrayOfint4) {
    for (byte b = 0; b < 10; b++) {
      int i = paramArrayOfint1[b];
      int j = paramArrayOfint2[b];
      paramArrayOfint3[b] = i + j;
      paramArrayOfint4[b] = i - j;
    } 
  }
  
  public static int areEqual(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = 0;
    for (byte b = 0; b < 10; b++)
      i |= paramArrayOfint1[b] ^ paramArrayOfint2[b]; 
    i = i >>> 1 | i & 0x1;
    return i - 1 >> 31;
  }
  
  public static boolean areEqualVar(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    return (0 != areEqual(paramArrayOfint1, paramArrayOfint2));
  }
  
  public static void carry(int[] paramArrayOfint) {
    int i = paramArrayOfint[0];
    int j = paramArrayOfint[1];
    int k = paramArrayOfint[2];
    int m = paramArrayOfint[3];
    int n = paramArrayOfint[4];
    int i1 = paramArrayOfint[5];
    int i2 = paramArrayOfint[6];
    int i3 = paramArrayOfint[7];
    int i4 = paramArrayOfint[8];
    int i5 = paramArrayOfint[9];
    k += j >> 26;
    j &= 0x3FFFFFF;
    n += m >> 26;
    m &= 0x3FFFFFF;
    i3 += i2 >> 26;
    i2 &= 0x3FFFFFF;
    i5 += i4 >> 26;
    i4 &= 0x3FFFFFF;
    m += k >> 25;
    k &= 0x1FFFFFF;
    i1 += n >> 25;
    n &= 0x1FFFFFF;
    i4 += i3 >> 25;
    i3 &= 0x1FFFFFF;
    i += (i5 >> 25) * 38;
    i5 &= 0x1FFFFFF;
    j += i >> 26;
    i &= 0x3FFFFFF;
    i2 += i1 >> 26;
    i1 &= 0x3FFFFFF;
    k += j >> 26;
    j &= 0x3FFFFFF;
    n += m >> 26;
    m &= 0x3FFFFFF;
    i3 += i2 >> 26;
    i2 &= 0x3FFFFFF;
    i5 += i4 >> 26;
    i4 &= 0x3FFFFFF;
    paramArrayOfint[0] = i;
    paramArrayOfint[1] = j;
    paramArrayOfint[2] = k;
    paramArrayOfint[3] = m;
    paramArrayOfint[4] = n;
    paramArrayOfint[5] = i1;
    paramArrayOfint[6] = i2;
    paramArrayOfint[7] = i3;
    paramArrayOfint[8] = i4;
    paramArrayOfint[9] = i5;
  }
  
  public static void cmov(int paramInt1, int[] paramArrayOfint1, int paramInt2, int[] paramArrayOfint2, int paramInt3) {
    for (byte b = 0; b < 10; b++) {
      int i = paramArrayOfint2[paramInt3 + b];
      int j = i ^ paramArrayOfint1[paramInt2 + b];
      i ^= j & paramInt1;
      paramArrayOfint2[paramInt3 + b] = i;
    } 
  }
  
  public static void cnegate(int paramInt, int[] paramArrayOfint) {
    int i = 0 - paramInt;
    for (byte b = 0; b < 10; b++)
      paramArrayOfint[b] = (paramArrayOfint[b] ^ i) - i; 
  }
  
  public static void copy(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    for (byte b = 0; b < 10; b++)
      paramArrayOfint2[paramInt2 + b] = paramArrayOfint1[paramInt1 + b]; 
  }
  
  public static int[] create() {
    return new int[10];
  }
  
  public static int[] createTable(int paramInt) {
    return new int[10 * paramInt];
  }
  
  public static void cswap(int paramInt, int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = 0 - paramInt;
    for (byte b = 0; b < 10; b++) {
      int j = paramArrayOfint1[b];
      int k = paramArrayOfint2[b];
      int m = i & (j ^ k);
      paramArrayOfint1[b] = j ^ m;
      paramArrayOfint2[b] = k ^ m;
    } 
  }
  
  public static void decode(int[] paramArrayOfint1, int paramInt, int[] paramArrayOfint2) {
    decode128(paramArrayOfint1, paramInt, paramArrayOfint2, 0);
    decode128(paramArrayOfint1, paramInt + 4, paramArrayOfint2, 5);
    paramArrayOfint2[9] = paramArrayOfint2[9] & 0xFFFFFF;
  }
  
  public static void decode(byte[] paramArrayOfbyte, int paramInt, int[] paramArrayOfint) {
    decode128(paramArrayOfbyte, paramInt, paramArrayOfint, 0);
    decode128(paramArrayOfbyte, paramInt + 16, paramArrayOfint, 5);
    paramArrayOfint[9] = paramArrayOfint[9] & 0xFFFFFF;
  }
  
  private static void decode128(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    int i = paramArrayOfint1[paramInt1 + 0];
    int j = paramArrayOfint1[paramInt1 + 1];
    int k = paramArrayOfint1[paramInt1 + 2];
    int m = paramArrayOfint1[paramInt1 + 3];
    paramArrayOfint2[paramInt2 + 0] = i & 0x3FFFFFF;
    paramArrayOfint2[paramInt2 + 1] = (j << 6 | i >>> 26) & 0x3FFFFFF;
    paramArrayOfint2[paramInt2 + 2] = (k << 12 | j >>> 20) & 0x1FFFFFF;
    paramArrayOfint2[paramInt2 + 3] = (m << 19 | k >>> 13) & 0x3FFFFFF;
    paramArrayOfint2[paramInt2 + 4] = m >>> 7;
  }
  
  private static void decode128(byte[] paramArrayOfbyte, int paramInt1, int[] paramArrayOfint, int paramInt2) {
    int i = decode32(paramArrayOfbyte, paramInt1 + 0);
    int j = decode32(paramArrayOfbyte, paramInt1 + 4);
    int k = decode32(paramArrayOfbyte, paramInt1 + 8);
    int m = decode32(paramArrayOfbyte, paramInt1 + 12);
    paramArrayOfint[paramInt2 + 0] = i & 0x3FFFFFF;
    paramArrayOfint[paramInt2 + 1] = (j << 6 | i >>> 26) & 0x3FFFFFF;
    paramArrayOfint[paramInt2 + 2] = (k << 12 | j >>> 20) & 0x1FFFFFF;
    paramArrayOfint[paramInt2 + 3] = (m << 19 | k >>> 13) & 0x3FFFFFF;
    paramArrayOfint[paramInt2 + 4] = m >>> 7;
  }
  
  private static int decode32(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    i |= paramArrayOfbyte[++paramInt] << 24;
    return i;
  }
  
  public static void encode(int[] paramArrayOfint1, int[] paramArrayOfint2, int paramInt) {
    encode128(paramArrayOfint1, 0, paramArrayOfint2, paramInt);
    encode128(paramArrayOfint1, 5, paramArrayOfint2, paramInt + 4);
  }
  
  public static void encode(int[] paramArrayOfint, byte[] paramArrayOfbyte, int paramInt) {
    encode128(paramArrayOfint, 0, paramArrayOfbyte, paramInt);
    encode128(paramArrayOfint, 5, paramArrayOfbyte, paramInt + 16);
  }
  
  private static void encode128(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    int i = paramArrayOfint1[paramInt1 + 0];
    int j = paramArrayOfint1[paramInt1 + 1];
    int k = paramArrayOfint1[paramInt1 + 2];
    int m = paramArrayOfint1[paramInt1 + 3];
    int n = paramArrayOfint1[paramInt1 + 4];
    paramArrayOfint2[paramInt2 + 0] = i | j << 26;
    paramArrayOfint2[paramInt2 + 1] = j >>> 6 | k << 20;
    paramArrayOfint2[paramInt2 + 2] = k >>> 12 | m << 13;
    paramArrayOfint2[paramInt2 + 3] = m >>> 19 | n << 7;
  }
  
  private static void encode128(int[] paramArrayOfint, int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    int i = paramArrayOfint[paramInt1 + 0];
    int j = paramArrayOfint[paramInt1 + 1];
    int k = paramArrayOfint[paramInt1 + 2];
    int m = paramArrayOfint[paramInt1 + 3];
    int n = paramArrayOfint[paramInt1 + 4];
    int i1 = i | j << 26;
    encode32(i1, paramArrayOfbyte, paramInt2 + 0);
    int i2 = j >>> 6 | k << 20;
    encode32(i2, paramArrayOfbyte, paramInt2 + 4);
    int i3 = k >>> 12 | m << 13;
    encode32(i3, paramArrayOfbyte, paramInt2 + 8);
    int i4 = m >>> 19 | n << 7;
    encode32(i4, paramArrayOfbyte, paramInt2 + 12);
  }
  
  private static void encode32(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    paramArrayOfbyte[paramInt2] = (byte)paramInt1;
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 8);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 16);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 24);
  }
  
  public static void inv(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = create();
    int[] arrayOfInt2 = new int[8];
    copy(paramArrayOfint1, 0, arrayOfInt1, 0);
    normalize(arrayOfInt1);
    encode(arrayOfInt1, arrayOfInt2, 0);
    Mod.modOddInverse(P32, arrayOfInt2, arrayOfInt2);
    decode(arrayOfInt2, 0, paramArrayOfint2);
  }
  
  public static void invVar(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = create();
    int[] arrayOfInt2 = new int[8];
    copy(paramArrayOfint1, 0, arrayOfInt1, 0);
    normalize(arrayOfInt1);
    encode(arrayOfInt1, arrayOfInt2, 0);
    Mod.modOddInverseVar(P32, arrayOfInt2, arrayOfInt2);
    decode(arrayOfInt2, 0, paramArrayOfint2);
  }
  
  public static int isOne(int[] paramArrayOfint) {
    int i = paramArrayOfint[0] ^ 0x1;
    for (byte b = 1; b < 10; b++)
      i |= paramArrayOfint[b]; 
    i = i >>> 1 | i & 0x1;
    return i - 1 >> 31;
  }
  
  public static boolean isOneVar(int[] paramArrayOfint) {
    return (0 != isOne(paramArrayOfint));
  }
  
  public static int isZero(int[] paramArrayOfint) {
    int i = 0;
    for (byte b = 0; b < 10; b++)
      i |= paramArrayOfint[b]; 
    i = i >>> 1 | i & 0x1;
    return i - 1 >> 31;
  }
  
  public static boolean isZeroVar(int[] paramArrayOfint) {
    return (0 != isZero(paramArrayOfint));
  }
  
  public static void mul(int[] paramArrayOfint1, int paramInt, int[] paramArrayOfint2) {
    int i = paramArrayOfint1[0];
    int j = paramArrayOfint1[1];
    int k = paramArrayOfint1[2];
    int m = paramArrayOfint1[3];
    int n = paramArrayOfint1[4];
    int i1 = paramArrayOfint1[5];
    int i2 = paramArrayOfint1[6];
    int i3 = paramArrayOfint1[7];
    int i4 = paramArrayOfint1[8];
    int i5 = paramArrayOfint1[9];
    long l1 = k * paramInt;
    k = (int)l1 & 0x1FFFFFF;
    l1 >>= 25L;
    long l2 = n * paramInt;
    n = (int)l2 & 0x1FFFFFF;
    l2 >>= 25L;
    long l3 = i3 * paramInt;
    i3 = (int)l3 & 0x1FFFFFF;
    l3 >>= 25L;
    long l4 = i5 * paramInt;
    i5 = (int)l4 & 0x1FFFFFF;
    l4 >>= 25L;
    l4 *= 38L;
    l4 += i * paramInt;
    paramArrayOfint2[0] = (int)l4 & 0x3FFFFFF;
    l4 >>= 26L;
    l2 += i1 * paramInt;
    paramArrayOfint2[5] = (int)l2 & 0x3FFFFFF;
    l2 >>= 26L;
    l4 += j * paramInt;
    paramArrayOfint2[1] = (int)l4 & 0x3FFFFFF;
    l4 >>= 26L;
    l1 += m * paramInt;
    paramArrayOfint2[3] = (int)l1 & 0x3FFFFFF;
    l1 >>= 26L;
    l2 += i2 * paramInt;
    paramArrayOfint2[6] = (int)l2 & 0x3FFFFFF;
    l2 >>= 26L;
    l3 += i4 * paramInt;
    paramArrayOfint2[8] = (int)l3 & 0x3FFFFFF;
    l3 >>= 26L;
    paramArrayOfint2[2] = k + (int)l4;
    paramArrayOfint2[4] = n + (int)l1;
    paramArrayOfint2[7] = i3 + (int)l2;
    paramArrayOfint2[9] = i5 + (int)l3;
  }
  
  public static void mul(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int i = paramArrayOfint1[0];
    int j = paramArrayOfint2[0];
    int k = paramArrayOfint1[1];
    int m = paramArrayOfint2[1];
    int n = paramArrayOfint1[2];
    int i1 = paramArrayOfint2[2];
    int i2 = paramArrayOfint1[3];
    int i3 = paramArrayOfint2[3];
    int i4 = paramArrayOfint1[4];
    int i5 = paramArrayOfint2[4];
    int i6 = paramArrayOfint1[5];
    int i7 = paramArrayOfint2[5];
    int i8 = paramArrayOfint1[6];
    int i9 = paramArrayOfint2[6];
    int i10 = paramArrayOfint1[7];
    int i11 = paramArrayOfint2[7];
    int i12 = paramArrayOfint1[8];
    int i13 = paramArrayOfint2[8];
    int i14 = paramArrayOfint1[9];
    int i15 = paramArrayOfint2[9];
    long l1 = i * j;
    long l2 = i * m + k * j;
    long l3 = i * i1 + k * m + n * j;
    long l4 = k * i1 + n * m;
    l4 <<= 1L;
    l4 += i * i3 + i2 * j;
    long l5 = n * i1;
    l5 <<= 1L;
    l5 += i * i5 + k * i3 + i2 * m + i4 * j;
    long l6 = k * i5 + n * i3 + i2 * i1 + i4 * m;
    l6 <<= 1L;
    long l7 = n * i5 + i4 * i1;
    l7 <<= 1L;
    l7 += i2 * i3;
    long l8 = i2 * i5 + i4 * i3;
    long l9 = i4 * i5;
    l9 <<= 1L;
    long l10 = i6 * i7;
    long l11 = i6 * i9 + i8 * i7;
    long l12 = i6 * i11 + i8 * i9 + i10 * i7;
    long l13 = i8 * i11 + i10 * i9;
    l13 <<= 1L;
    l13 += i6 * i13 + i12 * i7;
    long l14 = i10 * i11;
    l14 <<= 1L;
    l14 += i6 * i15 + i8 * i13 + i12 * i9 + i14 * i7;
    long l15 = i8 * i15 + i10 * i13 + i12 * i11 + i14 * i9;
    long l16 = i10 * i15 + i14 * i11;
    l16 <<= 1L;
    l16 += i12 * i13;
    long l17 = i12 * i15 + i14 * i13;
    long l18 = i14 * i15;
    l1 -= l15 * 76L;
    l2 -= l16 * 38L;
    l3 -= l17 * 38L;
    l4 -= l18 * 76L;
    l6 -= l10;
    l7 -= l11;
    l8 -= l12;
    l9 -= l13;
    i += i6;
    j += i7;
    k += i8;
    m += i9;
    n += i10;
    i1 += i11;
    i2 += i12;
    i3 += i13;
    i4 += i14;
    i5 += i15;
    long l19 = i * j;
    long l20 = i * m + k * j;
    long l21 = i * i1 + k * m + n * j;
    long l22 = k * i1 + n * m;
    l22 <<= 1L;
    l22 += i * i3 + i2 * j;
    long l23 = n * i1;
    l23 <<= 1L;
    l23 += i * i5 + k * i3 + i2 * m + i4 * j;
    long l24 = k * i5 + n * i3 + i2 * i1 + i4 * m;
    l24 <<= 1L;
    long l25 = n * i5 + i4 * i1;
    l25 <<= 1L;
    l25 += i2 * i3;
    long l26 = i2 * i5 + i4 * i3;
    long l27 = i4 * i5;
    l27 <<= 1L;
    long l28 = l9 + l22 - l4;
    int i16 = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l23 - l5 - l14;
    int i17 = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 = l1 + (l28 + l24 - l6) * 38L;
    paramArrayOfint3[0] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l2 + (l25 - l7) * 38L;
    paramArrayOfint3[1] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l3 + (l26 - l8) * 38L;
    paramArrayOfint3[2] = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 += l4 + (l27 - l9) * 38L;
    paramArrayOfint3[3] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l5 + l14 * 38L;
    paramArrayOfint3[4] = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 += l6 + l19 - l1;
    paramArrayOfint3[5] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l7 + l20 - l2;
    paramArrayOfint3[6] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l8 + l21 - l3;
    paramArrayOfint3[7] = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 += i16;
    paramArrayOfint3[8] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    paramArrayOfint3[9] = i17 + (int)l28;
  }
  
  public static void negate(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    for (byte b = 0; b < 10; b++)
      paramArrayOfint2[b] = -paramArrayOfint1[b]; 
  }
  
  public static void normalize(int[] paramArrayOfint) {
    int i = paramArrayOfint[9] >>> 23 & 0x1;
    reduce(paramArrayOfint, i);
    reduce(paramArrayOfint, -i);
  }
  
  public static void one(int[] paramArrayOfint) {
    paramArrayOfint[0] = 1;
    for (byte b = 1; b < 10; b++)
      paramArrayOfint[b] = 0; 
  }
  
  private static void powPm5d8(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int[] arrayOfInt1 = paramArrayOfint2;
    sqr(paramArrayOfint1, arrayOfInt1);
    mul(paramArrayOfint1, arrayOfInt1, arrayOfInt1);
    int[] arrayOfInt2 = create();
    sqr(arrayOfInt1, arrayOfInt2);
    mul(paramArrayOfint1, arrayOfInt2, arrayOfInt2);
    int[] arrayOfInt3 = arrayOfInt2;
    sqr(arrayOfInt2, 2, arrayOfInt3);
    mul(arrayOfInt1, arrayOfInt3, arrayOfInt3);
    int[] arrayOfInt4 = create();
    sqr(arrayOfInt3, 5, arrayOfInt4);
    mul(arrayOfInt3, arrayOfInt4, arrayOfInt4);
    int[] arrayOfInt5 = create();
    sqr(arrayOfInt4, 5, arrayOfInt5);
    mul(arrayOfInt3, arrayOfInt5, arrayOfInt5);
    int[] arrayOfInt6 = arrayOfInt3;
    sqr(arrayOfInt5, 10, arrayOfInt6);
    mul(arrayOfInt4, arrayOfInt6, arrayOfInt6);
    int[] arrayOfInt7 = arrayOfInt4;
    sqr(arrayOfInt6, 25, arrayOfInt7);
    mul(arrayOfInt6, arrayOfInt7, arrayOfInt7);
    int[] arrayOfInt8 = arrayOfInt5;
    sqr(arrayOfInt7, 25, arrayOfInt8);
    mul(arrayOfInt6, arrayOfInt8, arrayOfInt8);
    int[] arrayOfInt9 = arrayOfInt6;
    sqr(arrayOfInt8, 50, arrayOfInt9);
    mul(arrayOfInt7, arrayOfInt9, arrayOfInt9);
    int[] arrayOfInt10 = arrayOfInt7;
    sqr(arrayOfInt9, 125, arrayOfInt10);
    mul(arrayOfInt9, arrayOfInt10, arrayOfInt10);
    int[] arrayOfInt11 = arrayOfInt9;
    sqr(arrayOfInt10, 2, arrayOfInt11);
    mul(arrayOfInt11, paramArrayOfint1, paramArrayOfint3);
  }
  
  private static void reduce(int[] paramArrayOfint, int paramInt) {
    int i = paramArrayOfint[9];
    int j = i & 0xFFFFFF;
    i = (i >> 24) + paramInt;
    long l = (i * 19);
    l += paramArrayOfint[0];
    paramArrayOfint[0] = (int)l & 0x3FFFFFF;
    l >>= 26L;
    l += paramArrayOfint[1];
    paramArrayOfint[1] = (int)l & 0x3FFFFFF;
    l >>= 26L;
    l += paramArrayOfint[2];
    paramArrayOfint[2] = (int)l & 0x1FFFFFF;
    l >>= 25L;
    l += paramArrayOfint[3];
    paramArrayOfint[3] = (int)l & 0x3FFFFFF;
    l >>= 26L;
    l += paramArrayOfint[4];
    paramArrayOfint[4] = (int)l & 0x1FFFFFF;
    l >>= 25L;
    l += paramArrayOfint[5];
    paramArrayOfint[5] = (int)l & 0x3FFFFFF;
    l >>= 26L;
    l += paramArrayOfint[6];
    paramArrayOfint[6] = (int)l & 0x3FFFFFF;
    l >>= 26L;
    l += paramArrayOfint[7];
    paramArrayOfint[7] = (int)l & 0x1FFFFFF;
    l >>= 25L;
    l += paramArrayOfint[8];
    paramArrayOfint[8] = (int)l & 0x3FFFFFF;
    l >>= 26L;
    paramArrayOfint[9] = j + (int)l;
  }
  
  public static void sqr(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = paramArrayOfint1[0];
    int j = paramArrayOfint1[1];
    int k = paramArrayOfint1[2];
    int m = paramArrayOfint1[3];
    int n = paramArrayOfint1[4];
    int i1 = paramArrayOfint1[5];
    int i2 = paramArrayOfint1[6];
    int i3 = paramArrayOfint1[7];
    int i4 = paramArrayOfint1[8];
    int i5 = paramArrayOfint1[9];
    int i6 = j * 2;
    int i7 = k * 2;
    int i8 = m * 2;
    int i9 = n * 2;
    long l1 = i * i;
    long l2 = i * i6;
    long l3 = i * i7 + j * j;
    long l4 = i6 * i7 + i * i8;
    long l5 = k * i7 + i * i9 + j * i8;
    long l6 = i6 * i9 + i7 * i8;
    long l7 = i7 * i9 + m * m;
    long l8 = m * i9;
    long l9 = n * i9;
    int i10 = i2 * 2;
    int i11 = i3 * 2;
    int i12 = i4 * 2;
    int i13 = i5 * 2;
    long l10 = i1 * i1;
    long l11 = i1 * i10;
    long l12 = i1 * i11 + i2 * i2;
    long l13 = i10 * i11 + i1 * i12;
    long l14 = i3 * i11 + i1 * i13 + i2 * i12;
    long l15 = i10 * i13 + i11 * i12;
    long l16 = i11 * i13 + i4 * i4;
    long l17 = i4 * i13;
    long l18 = i5 * i13;
    l1 -= l15 * 38L;
    l2 -= l16 * 38L;
    l3 -= l17 * 38L;
    l4 -= l18 * 38L;
    l6 -= l10;
    l7 -= l11;
    l8 -= l12;
    l9 -= l13;
    i += i1;
    j += i2;
    k += i3;
    m += i4;
    n += i5;
    i6 = j * 2;
    i7 = k * 2;
    i8 = m * 2;
    i9 = n * 2;
    long l19 = i * i;
    long l20 = i * i6;
    long l21 = i * i7 + j * j;
    long l22 = i6 * i7 + i * i8;
    long l23 = k * i7 + i * i9 + j * i8;
    long l24 = i6 * i9 + i7 * i8;
    long l25 = i7 * i9 + m * m;
    long l26 = m * i9;
    long l27 = n * i9;
    long l28 = l9 + l22 - l4;
    int i14 = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l23 - l5 - l14;
    int i15 = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 = l1 + (l28 + l24 - l6) * 38L;
    paramArrayOfint2[0] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l2 + (l25 - l7) * 38L;
    paramArrayOfint2[1] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l3 + (l26 - l8) * 38L;
    paramArrayOfint2[2] = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 += l4 + (l27 - l9) * 38L;
    paramArrayOfint2[3] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l5 + l14 * 38L;
    paramArrayOfint2[4] = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 += l6 + l19 - l1;
    paramArrayOfint2[5] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l7 + l20 - l2;
    paramArrayOfint2[6] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    l28 += l8 + l21 - l3;
    paramArrayOfint2[7] = (int)l28 & 0x1FFFFFF;
    l28 >>= 25L;
    l28 += i14;
    paramArrayOfint2[8] = (int)l28 & 0x3FFFFFF;
    l28 >>= 26L;
    paramArrayOfint2[9] = i15 + (int)l28;
  }
  
  public static void sqr(int[] paramArrayOfint1, int paramInt, int[] paramArrayOfint2) {
    sqr(paramArrayOfint1, paramArrayOfint2);
    while (--paramInt > 0)
      sqr(paramArrayOfint2, paramArrayOfint2); 
  }
  
  public static boolean sqrtRatioVar(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int[] arrayOfInt1 = create();
    int[] arrayOfInt2 = create();
    mul(paramArrayOfint1, paramArrayOfint2, arrayOfInt1);
    sqr(paramArrayOfint2, arrayOfInt2);
    mul(arrayOfInt1, arrayOfInt2, arrayOfInt1);
    sqr(arrayOfInt2, arrayOfInt2);
    mul(arrayOfInt2, arrayOfInt1, arrayOfInt2);
    int[] arrayOfInt3 = create();
    int[] arrayOfInt4 = create();
    powPm5d8(arrayOfInt2, arrayOfInt3, arrayOfInt4);
    mul(arrayOfInt4, arrayOfInt1, arrayOfInt4);
    int[] arrayOfInt5 = create();
    sqr(arrayOfInt4, arrayOfInt5);
    mul(arrayOfInt5, paramArrayOfint2, arrayOfInt5);
    sub(arrayOfInt5, paramArrayOfint1, arrayOfInt3);
    normalize(arrayOfInt3);
    if (isZeroVar(arrayOfInt3)) {
      copy(arrayOfInt4, 0, paramArrayOfint3, 0);
      return true;
    } 
    add(arrayOfInt5, paramArrayOfint1, arrayOfInt3);
    normalize(arrayOfInt3);
    if (isZeroVar(arrayOfInt3)) {
      mul(arrayOfInt4, ROOT_NEG_ONE, paramArrayOfint3);
      return true;
    } 
    return false;
  }
  
  public static void sub(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    for (byte b = 0; b < 10; b++)
      paramArrayOfint3[b] = paramArrayOfint1[b] - paramArrayOfint2[b]; 
  }
  
  public static void subOne(int[] paramArrayOfint) {
    paramArrayOfint[0] = paramArrayOfint[0] - 1;
  }
  
  public static void zero(int[] paramArrayOfint) {
    for (byte b = 0; b < 10; b++)
      paramArrayOfint[b] = 0; 
  }
}
