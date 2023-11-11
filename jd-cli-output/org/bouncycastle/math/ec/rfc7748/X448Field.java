package org.bouncycastle.math.ec.rfc7748;

import org.bouncycastle.math.raw.Mod;

public abstract class X448Field {
  public static final int SIZE = 16;
  
  private static final int M28 = 268435455;
  
  private static final long U32 = 4294967295L;
  
  private static final int[] P32 = new int[] { 
      -1, -1, -1, -1, -1, -1, -1, -2, -1, -1, 
      -1, -1, -1, -1 };
  
  public static void add(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    for (byte b = 0; b < 16; b++)
      paramArrayOfint3[b] = paramArrayOfint1[b] + paramArrayOfint2[b]; 
  }
  
  public static void addOne(int[] paramArrayOfint) {
    paramArrayOfint[0] = paramArrayOfint[0] + 1;
  }
  
  public static void addOne(int[] paramArrayOfint, int paramInt) {
    paramArrayOfint[paramInt] = paramArrayOfint[paramInt] + 1;
  }
  
  public static int areEqual(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = 0;
    for (byte b = 0; b < 16; b++)
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
    int i6 = paramArrayOfint[10];
    int i7 = paramArrayOfint[11];
    int i8 = paramArrayOfint[12];
    int i9 = paramArrayOfint[13];
    int i10 = paramArrayOfint[14];
    int i11 = paramArrayOfint[15];
    j += i >>> 28;
    i &= 0xFFFFFFF;
    i1 += n >>> 28;
    n &= 0xFFFFFFF;
    i5 += i4 >>> 28;
    i4 &= 0xFFFFFFF;
    i9 += i8 >>> 28;
    i8 &= 0xFFFFFFF;
    k += j >>> 28;
    j &= 0xFFFFFFF;
    i2 += i1 >>> 28;
    i1 &= 0xFFFFFFF;
    i6 += i5 >>> 28;
    i5 &= 0xFFFFFFF;
    i10 += i9 >>> 28;
    i9 &= 0xFFFFFFF;
    m += k >>> 28;
    k &= 0xFFFFFFF;
    i3 += i2 >>> 28;
    i2 &= 0xFFFFFFF;
    i7 += i6 >>> 28;
    i6 &= 0xFFFFFFF;
    i11 += i10 >>> 28;
    i10 &= 0xFFFFFFF;
    int i12 = i11 >>> 28;
    i11 &= 0xFFFFFFF;
    i += i12;
    i4 += i12;
    n += m >>> 28;
    m &= 0xFFFFFFF;
    i4 += i3 >>> 28;
    i3 &= 0xFFFFFFF;
    i8 += i7 >>> 28;
    i7 &= 0xFFFFFFF;
    j += i >>> 28;
    i &= 0xFFFFFFF;
    i1 += n >>> 28;
    n &= 0xFFFFFFF;
    i5 += i4 >>> 28;
    i4 &= 0xFFFFFFF;
    i9 += i8 >>> 28;
    i8 &= 0xFFFFFFF;
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
    paramArrayOfint[10] = i6;
    paramArrayOfint[11] = i7;
    paramArrayOfint[12] = i8;
    paramArrayOfint[13] = i9;
    paramArrayOfint[14] = i10;
    paramArrayOfint[15] = i11;
  }
  
  public static void cmov(int paramInt1, int[] paramArrayOfint1, int paramInt2, int[] paramArrayOfint2, int paramInt3) {
    for (byte b = 0; b < 16; b++) {
      int i = paramArrayOfint2[paramInt3 + b];
      int j = i ^ paramArrayOfint1[paramInt2 + b];
      i ^= j & paramInt1;
      paramArrayOfint2[paramInt3 + b] = i;
    } 
  }
  
  public static void cnegate(int paramInt, int[] paramArrayOfint) {
    int[] arrayOfInt = create();
    sub(arrayOfInt, paramArrayOfint, arrayOfInt);
    cmov(-paramInt, arrayOfInt, 0, paramArrayOfint, 0);
  }
  
  public static void copy(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    for (byte b = 0; b < 16; b++)
      paramArrayOfint2[paramInt2 + b] = paramArrayOfint1[paramInt1 + b]; 
  }
  
  public static int[] create() {
    return new int[16];
  }
  
  public static int[] createTable(int paramInt) {
    return new int[16 * paramInt];
  }
  
  public static void cswap(int paramInt, int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = 0 - paramInt;
    for (byte b = 0; b < 16; b++) {
      int j = paramArrayOfint1[b];
      int k = paramArrayOfint2[b];
      int m = i & (j ^ k);
      paramArrayOfint1[b] = j ^ m;
      paramArrayOfint2[b] = k ^ m;
    } 
  }
  
  public static void decode(int[] paramArrayOfint1, int paramInt, int[] paramArrayOfint2) {
    decode224(paramArrayOfint1, paramInt, paramArrayOfint2, 0);
    decode224(paramArrayOfint1, paramInt + 7, paramArrayOfint2, 8);
  }
  
  public static void decode(byte[] paramArrayOfbyte, int paramInt, int[] paramArrayOfint) {
    decode56(paramArrayOfbyte, paramInt, paramArrayOfint, 0);
    decode56(paramArrayOfbyte, paramInt + 7, paramArrayOfint, 2);
    decode56(paramArrayOfbyte, paramInt + 14, paramArrayOfint, 4);
    decode56(paramArrayOfbyte, paramInt + 21, paramArrayOfint, 6);
    decode56(paramArrayOfbyte, paramInt + 28, paramArrayOfint, 8);
    decode56(paramArrayOfbyte, paramInt + 35, paramArrayOfint, 10);
    decode56(paramArrayOfbyte, paramInt + 42, paramArrayOfint, 12);
    decode56(paramArrayOfbyte, paramInt + 49, paramArrayOfint, 14);
  }
  
  private static void decode224(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    int i = paramArrayOfint1[paramInt1 + 0];
    int j = paramArrayOfint1[paramInt1 + 1];
    int k = paramArrayOfint1[paramInt1 + 2];
    int m = paramArrayOfint1[paramInt1 + 3];
    int n = paramArrayOfint1[paramInt1 + 4];
    int i1 = paramArrayOfint1[paramInt1 + 5];
    int i2 = paramArrayOfint1[paramInt1 + 6];
    paramArrayOfint2[paramInt2 + 0] = i & 0xFFFFFFF;
    paramArrayOfint2[paramInt2 + 1] = (i >>> 28 | j << 4) & 0xFFFFFFF;
    paramArrayOfint2[paramInt2 + 2] = (j >>> 24 | k << 8) & 0xFFFFFFF;
    paramArrayOfint2[paramInt2 + 3] = (k >>> 20 | m << 12) & 0xFFFFFFF;
    paramArrayOfint2[paramInt2 + 4] = (m >>> 16 | n << 16) & 0xFFFFFFF;
    paramArrayOfint2[paramInt2 + 5] = (n >>> 12 | i1 << 20) & 0xFFFFFFF;
    paramArrayOfint2[paramInt2 + 6] = (i1 >>> 8 | i2 << 24) & 0xFFFFFFF;
    paramArrayOfint2[paramInt2 + 7] = i2 >>> 4;
  }
  
  private static int decode24(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    return i;
  }
  
  private static int decode32(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    i |= paramArrayOfbyte[++paramInt] << 24;
    return i;
  }
  
  private static void decode56(byte[] paramArrayOfbyte, int paramInt1, int[] paramArrayOfint, int paramInt2) {
    int i = decode32(paramArrayOfbyte, paramInt1);
    int j = decode24(paramArrayOfbyte, paramInt1 + 4);
    paramArrayOfint[paramInt2] = i & 0xFFFFFFF;
    paramArrayOfint[paramInt2 + 1] = i >>> 28 | j << 4;
  }
  
  public static void encode(int[] paramArrayOfint1, int[] paramArrayOfint2, int paramInt) {
    encode224(paramArrayOfint1, 0, paramArrayOfint2, paramInt);
    encode224(paramArrayOfint1, 8, paramArrayOfint2, paramInt + 7);
  }
  
  public static void encode(int[] paramArrayOfint, byte[] paramArrayOfbyte, int paramInt) {
    encode56(paramArrayOfint, 0, paramArrayOfbyte, paramInt);
    encode56(paramArrayOfint, 2, paramArrayOfbyte, paramInt + 7);
    encode56(paramArrayOfint, 4, paramArrayOfbyte, paramInt + 14);
    encode56(paramArrayOfint, 6, paramArrayOfbyte, paramInt + 21);
    encode56(paramArrayOfint, 8, paramArrayOfbyte, paramInt + 28);
    encode56(paramArrayOfint, 10, paramArrayOfbyte, paramInt + 35);
    encode56(paramArrayOfint, 12, paramArrayOfbyte, paramInt + 42);
    encode56(paramArrayOfint, 14, paramArrayOfbyte, paramInt + 49);
  }
  
  private static void encode224(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    int i = paramArrayOfint1[paramInt1 + 0];
    int j = paramArrayOfint1[paramInt1 + 1];
    int k = paramArrayOfint1[paramInt1 + 2];
    int m = paramArrayOfint1[paramInt1 + 3];
    int n = paramArrayOfint1[paramInt1 + 4];
    int i1 = paramArrayOfint1[paramInt1 + 5];
    int i2 = paramArrayOfint1[paramInt1 + 6];
    int i3 = paramArrayOfint1[paramInt1 + 7];
    paramArrayOfint2[paramInt2 + 0] = i | j << 28;
    paramArrayOfint2[paramInt2 + 1] = j >>> 4 | k << 24;
    paramArrayOfint2[paramInt2 + 2] = k >>> 8 | m << 20;
    paramArrayOfint2[paramInt2 + 3] = m >>> 12 | n << 16;
    paramArrayOfint2[paramInt2 + 4] = n >>> 16 | i1 << 12;
    paramArrayOfint2[paramInt2 + 5] = i1 >>> 20 | i2 << 8;
    paramArrayOfint2[paramInt2 + 6] = i2 >>> 24 | i3 << 4;
  }
  
  private static void encode24(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    paramArrayOfbyte[paramInt2] = (byte)paramInt1;
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 8);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 16);
  }
  
  private static void encode32(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    paramArrayOfbyte[paramInt2] = (byte)paramInt1;
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 8);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 16);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 24);
  }
  
  private static void encode56(int[] paramArrayOfint, int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    int i = paramArrayOfint[paramInt1];
    int j = paramArrayOfint[paramInt1 + 1];
    encode32(i | j << 28, paramArrayOfbyte, paramInt2);
    encode24(j >>> 4, paramArrayOfbyte, paramInt2 + 4);
  }
  
  public static void inv(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = create();
    int[] arrayOfInt2 = new int[14];
    copy(paramArrayOfint1, 0, arrayOfInt1, 0);
    normalize(arrayOfInt1);
    encode(arrayOfInt1, arrayOfInt2, 0);
    Mod.modOddInverse(P32, arrayOfInt2, arrayOfInt2);
    decode(arrayOfInt2, 0, paramArrayOfint2);
  }
  
  public static void invVar(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = create();
    int[] arrayOfInt2 = new int[14];
    copy(paramArrayOfint1, 0, arrayOfInt1, 0);
    normalize(arrayOfInt1);
    encode(arrayOfInt1, arrayOfInt2, 0);
    Mod.modOddInverseVar(P32, arrayOfInt2, arrayOfInt2);
    decode(arrayOfInt2, 0, paramArrayOfint2);
  }
  
  public static int isOne(int[] paramArrayOfint) {
    int i = paramArrayOfint[0] ^ 0x1;
    for (byte b = 1; b < 16; b++)
      i |= paramArrayOfint[b]; 
    i = i >>> 1 | i & 0x1;
    return i - 1 >> 31;
  }
  
  public static boolean isOneVar(int[] paramArrayOfint) {
    return (0 != isOne(paramArrayOfint));
  }
  
  public static int isZero(int[] paramArrayOfint) {
    int i = 0;
    for (byte b = 0; b < 16; b++)
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
    int i6 = paramArrayOfint1[10];
    int i7 = paramArrayOfint1[11];
    int i8 = paramArrayOfint1[12];
    int i9 = paramArrayOfint1[13];
    int i10 = paramArrayOfint1[14];
    int i11 = paramArrayOfint1[15];
    long l1 = j * paramInt;
    int i12 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    long l2 = i1 * paramInt;
    int i13 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l3 = i5 * paramInt;
    int i14 = (int)l3 & 0xFFFFFFF;
    l3 >>>= 28L;
    long l4 = i9 * paramInt;
    int i15 = (int)l4 & 0xFFFFFFF;
    l4 >>>= 28L;
    l1 += k * paramInt;
    paramArrayOfint2[2] = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += i2 * paramInt;
    paramArrayOfint2[6] = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    l3 += i6 * paramInt;
    paramArrayOfint2[10] = (int)l3 & 0xFFFFFFF;
    l3 >>>= 28L;
    l4 += i10 * paramInt;
    paramArrayOfint2[14] = (int)l4 & 0xFFFFFFF;
    l4 >>>= 28L;
    l1 += m * paramInt;
    paramArrayOfint2[3] = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += i3 * paramInt;
    paramArrayOfint2[7] = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    l3 += i7 * paramInt;
    paramArrayOfint2[11] = (int)l3 & 0xFFFFFFF;
    l3 >>>= 28L;
    l4 += i11 * paramInt;
    paramArrayOfint2[15] = (int)l4 & 0xFFFFFFF;
    l4 >>>= 28L;
    l2 += l4;
    l1 += n * paramInt;
    paramArrayOfint2[4] = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += i4 * paramInt;
    paramArrayOfint2[8] = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    l3 += i8 * paramInt;
    paramArrayOfint2[12] = (int)l3 & 0xFFFFFFF;
    l3 >>>= 28L;
    l4 += i * paramInt;
    paramArrayOfint2[0] = (int)l4 & 0xFFFFFFF;
    l4 >>>= 28L;
    paramArrayOfint2[1] = i12 + (int)l4;
    paramArrayOfint2[5] = i13 + (int)l1;
    paramArrayOfint2[9] = i14 + (int)l2;
    paramArrayOfint2[13] = i15 + (int)l3;
  }
  
  public static void mul(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
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
    int i6 = paramArrayOfint1[10];
    int i7 = paramArrayOfint1[11];
    int i8 = paramArrayOfint1[12];
    int i9 = paramArrayOfint1[13];
    int i10 = paramArrayOfint1[14];
    int i11 = paramArrayOfint1[15];
    int i12 = paramArrayOfint2[0];
    int i13 = paramArrayOfint2[1];
    int i14 = paramArrayOfint2[2];
    int i15 = paramArrayOfint2[3];
    int i16 = paramArrayOfint2[4];
    int i17 = paramArrayOfint2[5];
    int i18 = paramArrayOfint2[6];
    int i19 = paramArrayOfint2[7];
    int i20 = paramArrayOfint2[8];
    int i21 = paramArrayOfint2[9];
    int i22 = paramArrayOfint2[10];
    int i23 = paramArrayOfint2[11];
    int i24 = paramArrayOfint2[12];
    int i25 = paramArrayOfint2[13];
    int i26 = paramArrayOfint2[14];
    int i27 = paramArrayOfint2[15];
    int i28 = i + i4;
    int i29 = j + i5;
    int i30 = k + i6;
    int i31 = m + i7;
    int i32 = n + i8;
    int i33 = i1 + i9;
    int i34 = i2 + i10;
    int i35 = i3 + i11;
    int i36 = i12 + i20;
    int i37 = i13 + i21;
    int i38 = i14 + i22;
    int i39 = i15 + i23;
    int i40 = i16 + i24;
    int i41 = i17 + i25;
    int i42 = i18 + i26;
    int i43 = i19 + i27;
    long l3 = i * i12;
    long l4 = i3 * i13 + i2 * i14 + i1 * i15 + n * i16 + m * i17 + k * i18 + j * i19;
    long l5 = i4 * i20;
    long l6 = i11 * i21 + i10 * i22 + i9 * i23 + i8 * i24 + i7 * i25 + i6 * i26 + i5 * i27;
    long l7 = i28 * i36;
    long l8 = i35 * i37 + i34 * i38 + i33 * i39 + i32 * i40 + i31 * i41 + i30 * i42 + i29 * i43;
    long l1 = l3 + l5 + l8 - l4;
    int i44 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    long l2 = l6 + l7 - l3 + l8;
    int i52 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l9 = j * i12 + i * i13;
    long l10 = i3 * i14 + i2 * i15 + i1 * i16 + n * i17 + m * i18 + k * i19;
    long l11 = i5 * i20 + i4 * i21;
    long l12 = i11 * i22 + i10 * i23 + i9 * i24 + i8 * i25 + i7 * i26 + i6 * i27;
    long l13 = i29 * i36 + i28 * i37;
    long l14 = i35 * i38 + i34 * i39 + i33 * i40 + i32 * i41 + i31 * i42 + i30 * i43;
    l1 += l9 + l11 + l14 - l10;
    int i45 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l12 + l13 - l9 + l14;
    int i53 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l15 = k * i12 + j * i13 + i * i14;
    long l16 = i3 * i15 + i2 * i16 + i1 * i17 + n * i18 + m * i19;
    long l17 = i6 * i20 + i5 * i21 + i4 * i22;
    long l18 = i11 * i23 + i10 * i24 + i9 * i25 + i8 * i26 + i7 * i27;
    long l19 = i30 * i36 + i29 * i37 + i28 * i38;
    long l20 = i35 * i39 + i34 * i40 + i33 * i41 + i32 * i42 + i31 * i43;
    l1 += l15 + l17 + l20 - l16;
    int i46 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l18 + l19 - l15 + l20;
    int i54 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l21 = m * i12 + k * i13 + j * i14 + i * i15;
    long l22 = i3 * i16 + i2 * i17 + i1 * i18 + n * i19;
    long l23 = i7 * i20 + i6 * i21 + i5 * i22 + i4 * i23;
    long l24 = i11 * i24 + i10 * i25 + i9 * i26 + i8 * i27;
    long l25 = i31 * i36 + i30 * i37 + i29 * i38 + i28 * i39;
    long l26 = i35 * i40 + i34 * i41 + i33 * i42 + i32 * i43;
    l1 += l21 + l23 + l26 - l22;
    int i47 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l24 + l25 - l21 + l26;
    int i55 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l27 = n * i12 + m * i13 + k * i14 + j * i15 + i * i16;
    long l28 = i3 * i17 + i2 * i18 + i1 * i19;
    long l29 = i8 * i20 + i7 * i21 + i6 * i22 + i5 * i23 + i4 * i24;
    long l30 = i11 * i25 + i10 * i26 + i9 * i27;
    long l31 = i32 * i36 + i31 * i37 + i30 * i38 + i29 * i39 + i28 * i40;
    long l32 = i35 * i41 + i34 * i42 + i33 * i43;
    l1 += l27 + l29 + l32 - l28;
    int i48 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l30 + l31 - l27 + l32;
    int i56 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l33 = i1 * i12 + n * i13 + m * i14 + k * i15 + j * i16 + i * i17;
    long l34 = i3 * i18 + i2 * i19;
    long l35 = i9 * i20 + i8 * i21 + i7 * i22 + i6 * i23 + i5 * i24 + i4 * i25;
    long l36 = i11 * i26 + i10 * i27;
    long l37 = i33 * i36 + i32 * i37 + i31 * i38 + i30 * i39 + i29 * i40 + i28 * i41;
    long l38 = i35 * i42 + i34 * i43;
    l1 += l33 + l35 + l38 - l34;
    int i49 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l36 + l37 - l33 + l38;
    int i57 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l39 = i2 * i12 + i1 * i13 + n * i14 + m * i15 + k * i16 + j * i17 + i * i18;
    long l40 = i3 * i19;
    long l41 = i10 * i20 + i9 * i21 + i8 * i22 + i7 * i23 + i6 * i24 + i5 * i25 + i4 * i26;
    long l42 = i11 * i27;
    long l43 = i34 * i36 + i33 * i37 + i32 * i38 + i31 * i39 + i30 * i40 + i29 * i41 + i28 * i42;
    long l44 = i35 * i43;
    l1 += l39 + l41 + l44 - l40;
    int i50 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l42 + l43 - l39 + l44;
    int i58 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l45 = i3 * i12 + i2 * i13 + i1 * i14 + n * i15 + m * i16 + k * i17 + j * i18 + i * i19;
    long l46 = i11 * i20 + i10 * i21 + i9 * i22 + i8 * i23 + i7 * i24 + i6 * i25 + i5 * i26 + i4 * i27;
    long l47 = i35 * i36 + i34 * i37 + i33 * i38 + i32 * i39 + i31 * i40 + i30 * i41 + i29 * i42 + i28 * i43;
    l1 += l45 + l46;
    int i51 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l47 - l45;
    int i59 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    l1 += l2;
    l1 += i52;
    i52 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += i44;
    i44 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    i53 += (int)l1;
    i45 += (int)l2;
    paramArrayOfint3[0] = i44;
    paramArrayOfint3[1] = i45;
    paramArrayOfint3[2] = i46;
    paramArrayOfint3[3] = i47;
    paramArrayOfint3[4] = i48;
    paramArrayOfint3[5] = i49;
    paramArrayOfint3[6] = i50;
    paramArrayOfint3[7] = i51;
    paramArrayOfint3[8] = i52;
    paramArrayOfint3[9] = i53;
    paramArrayOfint3[10] = i54;
    paramArrayOfint3[11] = i55;
    paramArrayOfint3[12] = i56;
    paramArrayOfint3[13] = i57;
    paramArrayOfint3[14] = i58;
    paramArrayOfint3[15] = i59;
  }
  
  public static void negate(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt = create();
    sub(arrayOfInt, paramArrayOfint1, paramArrayOfint2);
  }
  
  public static void normalize(int[] paramArrayOfint) {
    reduce(paramArrayOfint, 1);
    reduce(paramArrayOfint, -1);
  }
  
  public static void one(int[] paramArrayOfint) {
    paramArrayOfint[0] = 1;
    for (byte b = 1; b < 16; b++)
      paramArrayOfint[b] = 0; 
  }
  
  private static void powPm3d4(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = create();
    sqr(paramArrayOfint1, arrayOfInt1);
    mul(paramArrayOfint1, arrayOfInt1, arrayOfInt1);
    int[] arrayOfInt2 = create();
    sqr(arrayOfInt1, arrayOfInt2);
    mul(paramArrayOfint1, arrayOfInt2, arrayOfInt2);
    int[] arrayOfInt3 = create();
    sqr(arrayOfInt2, 3, arrayOfInt3);
    mul(arrayOfInt2, arrayOfInt3, arrayOfInt3);
    int[] arrayOfInt4 = create();
    sqr(arrayOfInt3, 3, arrayOfInt4);
    mul(arrayOfInt2, arrayOfInt4, arrayOfInt4);
    int[] arrayOfInt5 = create();
    sqr(arrayOfInt4, 9, arrayOfInt5);
    mul(arrayOfInt4, arrayOfInt5, arrayOfInt5);
    int[] arrayOfInt6 = create();
    sqr(arrayOfInt5, arrayOfInt6);
    mul(paramArrayOfint1, arrayOfInt6, arrayOfInt6);
    int[] arrayOfInt7 = create();
    sqr(arrayOfInt6, 18, arrayOfInt7);
    mul(arrayOfInt5, arrayOfInt7, arrayOfInt7);
    int[] arrayOfInt8 = create();
    sqr(arrayOfInt7, 37, arrayOfInt8);
    mul(arrayOfInt7, arrayOfInt8, arrayOfInt8);
    int[] arrayOfInt9 = create();
    sqr(arrayOfInt8, 37, arrayOfInt9);
    mul(arrayOfInt7, arrayOfInt9, arrayOfInt9);
    int[] arrayOfInt10 = create();
    sqr(arrayOfInt9, 111, arrayOfInt10);
    mul(arrayOfInt9, arrayOfInt10, arrayOfInt10);
    int[] arrayOfInt11 = create();
    sqr(arrayOfInt10, arrayOfInt11);
    mul(paramArrayOfint1, arrayOfInt11, arrayOfInt11);
    int[] arrayOfInt12 = create();
    sqr(arrayOfInt11, 223, arrayOfInt12);
    mul(arrayOfInt12, arrayOfInt10, paramArrayOfint2);
  }
  
  private static void reduce(int[] paramArrayOfint, int paramInt) {
    int i = paramArrayOfint[15];
    int j = i & 0xFFFFFFF;
    i = (i >>> 28) + paramInt;
    long l = i;
    byte b;
    for (b = 0; b < 8; b++) {
      l += paramArrayOfint[b] & 0xFFFFFFFFL;
      paramArrayOfint[b] = (int)l & 0xFFFFFFF;
      l >>= 28L;
    } 
    l += i;
    for (b = 8; b < 15; b++) {
      l += paramArrayOfint[b] & 0xFFFFFFFFL;
      paramArrayOfint[b] = (int)l & 0xFFFFFFF;
      l >>= 28L;
    } 
    paramArrayOfint[15] = j + (int)l;
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
    int i6 = paramArrayOfint1[10];
    int i7 = paramArrayOfint1[11];
    int i8 = paramArrayOfint1[12];
    int i9 = paramArrayOfint1[13];
    int i10 = paramArrayOfint1[14];
    int i11 = paramArrayOfint1[15];
    int i12 = i * 2;
    int i13 = j * 2;
    int i14 = k * 2;
    int i15 = m * 2;
    int i16 = n * 2;
    int i17 = i1 * 2;
    int i18 = i2 * 2;
    int i19 = i4 * 2;
    int i20 = i5 * 2;
    int i21 = i6 * 2;
    int i22 = i7 * 2;
    int i23 = i8 * 2;
    int i24 = i9 * 2;
    int i25 = i10 * 2;
    int i26 = i + i4;
    int i27 = j + i5;
    int i28 = k + i6;
    int i29 = m + i7;
    int i30 = n + i8;
    int i31 = i1 + i9;
    int i32 = i2 + i10;
    int i33 = i3 + i11;
    int i34 = i26 * 2;
    int i35 = i27 * 2;
    int i36 = i28 * 2;
    int i37 = i29 * 2;
    int i38 = i30 * 2;
    int i39 = i31 * 2;
    int i40 = i32 * 2;
    long l3 = i * i;
    long l4 = i3 * i13 + i2 * i14 + i1 * i15 + n * n;
    long l5 = i4 * i4;
    long l6 = i11 * i20 + i10 * i21 + i9 * i22 + i8 * i8;
    long l7 = i26 * i26;
    long l8 = i33 * (i35 & 0xFFFFFFFFL) + i32 * (i36 & 0xFFFFFFFFL) + i31 * (i37 & 0xFFFFFFFFL) + i30 * i30;
    long l1 = l3 + l5 + l8 - l4;
    int i41 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    long l2 = l6 + l7 - l3 + l8;
    int i49 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l9 = j * i12;
    long l10 = i3 * i14 + i2 * i15 + i1 * i16;
    long l11 = i5 * i19;
    long l12 = i11 * i21 + i10 * i22 + i9 * i23;
    long l13 = i27 * (i34 & 0xFFFFFFFFL);
    long l14 = i33 * (i36 & 0xFFFFFFFFL) + i32 * (i37 & 0xFFFFFFFFL) + i31 * (i38 & 0xFFFFFFFFL);
    l1 += l9 + l11 + l14 - l10;
    int i42 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l12 + l13 - l9 + l14;
    int i50 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l15 = k * i12 + j * j;
    long l16 = i3 * i15 + i2 * i16 + i1 * i1;
    long l17 = i6 * i19 + i5 * i5;
    long l18 = i11 * i22 + i10 * i23 + i9 * i9;
    long l19 = i28 * (i34 & 0xFFFFFFFFL) + i27 * i27;
    long l20 = i33 * (i37 & 0xFFFFFFFFL) + i32 * (i38 & 0xFFFFFFFFL) + i31 * i31;
    l1 += l15 + l17 + l20 - l16;
    int i43 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l18 + l19 - l15 + l20;
    int i51 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l21 = m * i12 + k * i13;
    long l22 = i3 * i16 + i2 * i17;
    long l23 = i7 * i19 + i6 * i20;
    long l24 = i11 * i23 + i10 * i24;
    long l25 = i29 * (i34 & 0xFFFFFFFFL) + i28 * (i35 & 0xFFFFFFFFL);
    long l26 = i33 * (i38 & 0xFFFFFFFFL) + i32 * (i39 & 0xFFFFFFFFL);
    l1 += l21 + l23 + l26 - l22;
    int i44 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l24 + l25 - l21 + l26;
    int i52 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l27 = n * i12 + m * i13 + k * k;
    long l28 = i3 * i17 + i2 * i2;
    long l29 = i8 * i19 + i7 * i20 + i6 * i6;
    long l30 = i11 * i24 + i10 * i10;
    long l31 = i30 * (i34 & 0xFFFFFFFFL) + i29 * (i35 & 0xFFFFFFFFL) + i28 * i28;
    long l32 = i33 * (i39 & 0xFFFFFFFFL) + i32 * i32;
    l1 += l27 + l29 + l32 - l28;
    int i45 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l30 + l31 - l27 + l32;
    int i53 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l33 = i1 * i12 + n * i13 + m * i14;
    long l34 = i3 * i18;
    long l35 = i9 * i19 + i8 * i20 + i7 * i21;
    long l36 = i11 * i25;
    long l37 = i31 * (i34 & 0xFFFFFFFFL) + i30 * (i35 & 0xFFFFFFFFL) + i29 * (i36 & 0xFFFFFFFFL);
    long l38 = i33 * (i40 & 0xFFFFFFFFL);
    l1 += l33 + l35 + l38 - l34;
    int i46 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l36 + l37 - l33 + l38;
    int i54 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l39 = i2 * i12 + i1 * i13 + n * i14 + m * m;
    long l40 = i3 * i3;
    long l41 = i10 * i19 + i9 * i20 + i8 * i21 + i7 * i7;
    long l42 = i11 * i11;
    long l43 = i32 * (i34 & 0xFFFFFFFFL) + i31 * (i35 & 0xFFFFFFFFL) + i30 * (i36 & 0xFFFFFFFFL) + i29 * i29;
    long l44 = i33 * i33;
    l1 += l39 + l41 + l44 - l40;
    int i47 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l42 + l43 - l39 + l44;
    int i55 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    long l45 = i3 * i12 + i2 * i13 + i1 * i14 + n * i15;
    long l46 = i11 * i19 + i10 * i20 + i9 * i21 + i8 * i22;
    long l47 = i33 * (i34 & 0xFFFFFFFFL) + i32 * (i35 & 0xFFFFFFFFL) + i31 * (i36 & 0xFFFFFFFFL) + i30 * (i37 & 0xFFFFFFFFL);
    l1 += l45 + l46;
    int i48 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += l47 - l45;
    int i56 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    l1 += l2;
    l1 += i49;
    i49 = (int)l1 & 0xFFFFFFF;
    l1 >>>= 28L;
    l2 += i41;
    i41 = (int)l2 & 0xFFFFFFF;
    l2 >>>= 28L;
    i50 += (int)l1;
    i42 += (int)l2;
    paramArrayOfint2[0] = i41;
    paramArrayOfint2[1] = i42;
    paramArrayOfint2[2] = i43;
    paramArrayOfint2[3] = i44;
    paramArrayOfint2[4] = i45;
    paramArrayOfint2[5] = i46;
    paramArrayOfint2[6] = i47;
    paramArrayOfint2[7] = i48;
    paramArrayOfint2[8] = i49;
    paramArrayOfint2[9] = i50;
    paramArrayOfint2[10] = i51;
    paramArrayOfint2[11] = i52;
    paramArrayOfint2[12] = i53;
    paramArrayOfint2[13] = i54;
    paramArrayOfint2[14] = i55;
    paramArrayOfint2[15] = i56;
  }
  
  public static void sqr(int[] paramArrayOfint1, int paramInt, int[] paramArrayOfint2) {
    sqr(paramArrayOfint1, paramArrayOfint2);
    while (--paramInt > 0)
      sqr(paramArrayOfint2, paramArrayOfint2); 
  }
  
  public static boolean sqrtRatioVar(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int[] arrayOfInt1 = create();
    int[] arrayOfInt2 = create();
    sqr(paramArrayOfint1, arrayOfInt1);
    mul(arrayOfInt1, paramArrayOfint2, arrayOfInt1);
    sqr(arrayOfInt1, arrayOfInt2);
    mul(arrayOfInt1, paramArrayOfint1, arrayOfInt1);
    mul(arrayOfInt2, paramArrayOfint1, arrayOfInt2);
    mul(arrayOfInt2, paramArrayOfint2, arrayOfInt2);
    int[] arrayOfInt3 = create();
    powPm3d4(arrayOfInt2, arrayOfInt3);
    mul(arrayOfInt3, arrayOfInt1, arrayOfInt3);
    int[] arrayOfInt4 = create();
    sqr(arrayOfInt3, arrayOfInt4);
    mul(arrayOfInt4, paramArrayOfint2, arrayOfInt4);
    sub(paramArrayOfint1, arrayOfInt4, arrayOfInt4);
    normalize(arrayOfInt4);
    if (isZeroVar(arrayOfInt4)) {
      copy(arrayOfInt3, 0, paramArrayOfint3, 0);
      return true;
    } 
    return false;
  }
  
  public static void sub(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
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
    int i6 = paramArrayOfint1[10];
    int i7 = paramArrayOfint1[11];
    int i8 = paramArrayOfint1[12];
    int i9 = paramArrayOfint1[13];
    int i10 = paramArrayOfint1[14];
    int i11 = paramArrayOfint1[15];
    int i12 = paramArrayOfint2[0];
    int i13 = paramArrayOfint2[1];
    int i14 = paramArrayOfint2[2];
    int i15 = paramArrayOfint2[3];
    int i16 = paramArrayOfint2[4];
    int i17 = paramArrayOfint2[5];
    int i18 = paramArrayOfint2[6];
    int i19 = paramArrayOfint2[7];
    int i20 = paramArrayOfint2[8];
    int i21 = paramArrayOfint2[9];
    int i22 = paramArrayOfint2[10];
    int i23 = paramArrayOfint2[11];
    int i24 = paramArrayOfint2[12];
    int i25 = paramArrayOfint2[13];
    int i26 = paramArrayOfint2[14];
    int i27 = paramArrayOfint2[15];
    int i28 = i + 536870910 - i12;
    int i29 = j + 536870910 - i13;
    int i30 = k + 536870910 - i14;
    int i31 = m + 536870910 - i15;
    int i32 = n + 536870910 - i16;
    int i33 = i1 + 536870910 - i17;
    int i34 = i2 + 536870910 - i18;
    int i35 = i3 + 536870910 - i19;
    int i36 = i4 + 536870908 - i20;
    int i37 = i5 + 536870910 - i21;
    int i38 = i6 + 536870910 - i22;
    int i39 = i7 + 536870910 - i23;
    int i40 = i8 + 536870910 - i24;
    int i41 = i9 + 536870910 - i25;
    int i42 = i10 + 536870910 - i26;
    int i43 = i11 + 536870910 - i27;
    i30 += i29 >>> 28;
    i29 &= 0xFFFFFFF;
    i34 += i33 >>> 28;
    i33 &= 0xFFFFFFF;
    i38 += i37 >>> 28;
    i37 &= 0xFFFFFFF;
    i42 += i41 >>> 28;
    i41 &= 0xFFFFFFF;
    i31 += i30 >>> 28;
    i30 &= 0xFFFFFFF;
    i35 += i34 >>> 28;
    i34 &= 0xFFFFFFF;
    i39 += i38 >>> 28;
    i38 &= 0xFFFFFFF;
    i43 += i42 >>> 28;
    i42 &= 0xFFFFFFF;
    int i44 = i43 >>> 28;
    i43 &= 0xFFFFFFF;
    i28 += i44;
    i36 += i44;
    i32 += i31 >>> 28;
    i31 &= 0xFFFFFFF;
    i36 += i35 >>> 28;
    i35 &= 0xFFFFFFF;
    i40 += i39 >>> 28;
    i39 &= 0xFFFFFFF;
    i29 += i28 >>> 28;
    i28 &= 0xFFFFFFF;
    i33 += i32 >>> 28;
    i32 &= 0xFFFFFFF;
    i37 += i36 >>> 28;
    i36 &= 0xFFFFFFF;
    i41 += i40 >>> 28;
    i40 &= 0xFFFFFFF;
    paramArrayOfint3[0] = i28;
    paramArrayOfint3[1] = i29;
    paramArrayOfint3[2] = i30;
    paramArrayOfint3[3] = i31;
    paramArrayOfint3[4] = i32;
    paramArrayOfint3[5] = i33;
    paramArrayOfint3[6] = i34;
    paramArrayOfint3[7] = i35;
    paramArrayOfint3[8] = i36;
    paramArrayOfint3[9] = i37;
    paramArrayOfint3[10] = i38;
    paramArrayOfint3[11] = i39;
    paramArrayOfint3[12] = i40;
    paramArrayOfint3[13] = i41;
    paramArrayOfint3[14] = i42;
    paramArrayOfint3[15] = i43;
  }
  
  public static void subOne(int[] paramArrayOfint) {
    int[] arrayOfInt = create();
    arrayOfInt[0] = 1;
    sub(paramArrayOfint, arrayOfInt, paramArrayOfint);
  }
  
  public static void zero(int[] paramArrayOfint) {
    for (byte b = 0; b < 16; b++)
      paramArrayOfint[b] = 0; 
  }
}
