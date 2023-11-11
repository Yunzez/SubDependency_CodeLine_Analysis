package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Pack;

public class AESLightEngine implements BlockCipher {
  private static final byte[] S = new byte[] { 
      99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 
      103, 43, -2, -41, -85, 118, -54, -126, -55, 125, 
      -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 
      114, -64, -73, -3, -109, 38, 54, 63, -9, -52, 
      52, -91, -27, -15, 113, -40, 49, 21, 4, -57, 
      35, -61, 24, -106, 5, -102, 7, 18, Byte.MIN_VALUE, -30, 
      -21, 39, -78, 117, 9, -125, 44, 26, 27, 110, 
      90, -96, 82, 59, -42, -77, 41, -29, 47, -124, 
      83, -47, 0, -19, 32, -4, -79, 91, 106, -53, 
      -66, 57, 74, 76, 88, -49, -48, -17, -86, -5, 
      67, 77, 51, -123, 69, -7, 2, Byte.MAX_VALUE, 80, 60, 
      -97, -88, 81, -93, 64, -113, -110, -99, 56, -11, 
      -68, -74, -38, 33, 16, -1, -13, -46, -51, 12, 
      19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 
      100, 93, 25, 115, 96, -127, 79, -36, 34, 42, 
      -112, -120, 70, -18, -72, 20, -34, 94, 11, -37, 
      -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, 
      -84, 98, -111, -107, -28, 121, -25, -56, 55, 109, 
      -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, 
      -82, 8, -70, 120, 37, 46, 28, -90, -76, -58, 
      -24, -35, 116, 31, 75, -67, -117, -118, 112, 62, 
      -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, 
      -122, -63, 29, -98, -31, -8, -104, 17, 105, -39, 
      -114, -108, -101, 30, -121, -23, -50, 85, 40, -33, 
      -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 
      45, 15, -80, 84, -69, 22 };
  
  private static final byte[] Si = new byte[] { 
      82, 9, 106, -43, 48, 54, -91, 56, -65, 64, 
      -93, -98, -127, -13, -41, -5, 124, -29, 57, -126, 
      -101, 47, -1, -121, 52, -114, 67, 68, -60, -34, 
      -23, -53, 84, 123, -108, 50, -90, -62, 35, 61, 
      -18, 76, -107, 11, 66, -6, -61, 78, 8, 46, 
      -95, 102, 40, -39, 36, -78, 118, 91, -94, 73, 
      109, -117, -47, 37, 114, -8, -10, 100, -122, 104, 
      -104, 22, -44, -92, 92, -52, 93, 101, -74, -110, 
      108, 112, 72, 80, -3, -19, -71, -38, 94, 21, 
      70, 87, -89, -115, -99, -124, -112, -40, -85, 0, 
      -116, -68, -45, 10, -9, -28, 88, 5, -72, -77, 
      69, 6, -48, 44, 30, -113, -54, 63, 15, 2, 
      -63, -81, -67, 3, 1, 19, -118, 107, 58, -111, 
      17, 65, 79, 103, -36, -22, -105, -14, -49, -50, 
      -16, -76, -26, 115, -106, -84, 116, 34, -25, -83, 
      53, -123, -30, -7, 55, -24, 28, 117, -33, 110, 
      71, -15, 26, 113, 29, 41, -59, -119, 111, -73, 
      98, 14, -86, 24, -66, 27, -4, 86, 62, 75, 
      -58, -46, 121, 32, -102, -37, -64, -2, 120, -51, 
      90, -12, 31, -35, -88, 51, -120, 7, -57, 49, 
      -79, 18, 16, 89, 39, Byte.MIN_VALUE, -20, 95, 96, 81, 
      Byte.MAX_VALUE, -87, 25, -75, 74, 13, 45, -27, 122, -97, 
      -109, -55, -100, -17, -96, -32, 59, 77, -82, 42, 
      -11, -80, -56, -21, -69, 60, -125, 83, -103, 97, 
      23, 43, 4, 126, -70, 119, -42, 38, -31, 105, 
      20, 99, 85, 33, 12, 125 };
  
  private static final int[] rcon = new int[] { 
      1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 
      108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 
      151, 53, 106, 212, 179, 125, 250, 239, 197, 145 };
  
  private static final int m1 = -2139062144;
  
  private static final int m2 = 2139062143;
  
  private static final int m3 = 27;
  
  private static final int m4 = -1061109568;
  
  private static final int m5 = 1061109567;
  
  private int ROUNDS;
  
  private int[][] WorkingKey = (int[][])null;
  
  private boolean forEncryption;
  
  private static final int BLOCK_SIZE = 16;
  
  private static int shift(int paramInt1, int paramInt2) {
    return paramInt1 >>> paramInt2 | paramInt1 << -paramInt2;
  }
  
  private static int FFmulX(int paramInt) {
    return (paramInt & 0x7F7F7F7F) << 1 ^ ((paramInt & 0x80808080) >>> 7) * 27;
  }
  
  private static int FFmulX2(int paramInt) {
    int i = (paramInt & 0x3F3F3F3F) << 2;
    int j = paramInt & 0xC0C0C0C0;
    j ^= j >>> 1;
    return i ^ j >>> 2 ^ j >>> 5;
  }
  
  private static int mcol(int paramInt) {
    int i = shift(paramInt, 8);
    int j = paramInt ^ i;
    return shift(j, 16) ^ i ^ FFmulX(j);
  }
  
  private static int inv_mcol(int paramInt) {
    int i = paramInt;
    int j = i ^ shift(i, 8);
    i ^= FFmulX(j);
    j ^= FFmulX2(i);
    i ^= j ^ shift(j, 16);
    return i;
  }
  
  private static int subWord(int paramInt) {
    return S[paramInt & 0xFF] & 0xFF | (S[paramInt >> 8 & 0xFF] & 0xFF) << 8 | (S[paramInt >> 16 & 0xFF] & 0xFF) << 16 | S[paramInt >> 24 & 0xFF] << 24;
  }
  
  private int[][] generateWorkingKey(byte[] paramArrayOfbyte, boolean paramBoolean) {
    int k;
    int m;
    int n;
    int i1;
    int i2;
    int i3;
    int i4;
    int i5;
    byte b;
    int i6;
    int i = paramArrayOfbyte.length;
    if (i < 16 || i > 32 || (i & 0x7) != 0)
      throw new IllegalArgumentException("Key length not 128/192/256 bits."); 
    int j = i >>> 2;
    this.ROUNDS = j + 6;
    int[][] arrayOfInt = new int[this.ROUNDS + 1][4];
    switch (j) {
      case 4:
        k = Pack.littleEndianToInt(paramArrayOfbyte, 0);
        arrayOfInt[0][0] = k;
        m = Pack.littleEndianToInt(paramArrayOfbyte, 4);
        arrayOfInt[0][1] = m;
        n = Pack.littleEndianToInt(paramArrayOfbyte, 8);
        arrayOfInt[0][2] = n;
        i1 = Pack.littleEndianToInt(paramArrayOfbyte, 12);
        arrayOfInt[0][3] = i1;
        for (i2 = 1; i2 <= 10; i2++) {
          int i7 = subWord(shift(i1, 8)) ^ rcon[i2 - 1];
          k ^= i7;
          arrayOfInt[i2][0] = k;
          m ^= k;
          arrayOfInt[i2][1] = m;
          n ^= m;
          arrayOfInt[i2][2] = n;
          i1 ^= n;
          arrayOfInt[i2][3] = i1;
        } 
        break;
      case 6:
        k = Pack.littleEndianToInt(paramArrayOfbyte, 0);
        arrayOfInt[0][0] = k;
        m = Pack.littleEndianToInt(paramArrayOfbyte, 4);
        arrayOfInt[0][1] = m;
        n = Pack.littleEndianToInt(paramArrayOfbyte, 8);
        arrayOfInt[0][2] = n;
        i1 = Pack.littleEndianToInt(paramArrayOfbyte, 12);
        arrayOfInt[0][3] = i1;
        i2 = Pack.littleEndianToInt(paramArrayOfbyte, 16);
        i3 = Pack.littleEndianToInt(paramArrayOfbyte, 20);
        i4 = 1;
        i5 = 1;
        while (true) {
          arrayOfInt[i4][0] = i2;
          arrayOfInt[i4][1] = i3;
          int i7 = subWord(shift(i3, 8)) ^ i5;
          i5 <<= 1;
          k ^= i7;
          arrayOfInt[i4][2] = k;
          m ^= k;
          arrayOfInt[i4][3] = m;
          n ^= m;
          arrayOfInt[i4 + 1][0] = n;
          i1 ^= n;
          arrayOfInt[i4 + 1][1] = i1;
          i2 ^= i1;
          arrayOfInt[i4 + 1][2] = i2;
          i3 ^= i2;
          arrayOfInt[i4 + 1][3] = i3;
          i7 = subWord(shift(i3, 8)) ^ i5;
          i5 <<= 1;
          k ^= i7;
          arrayOfInt[i4 + 2][0] = k;
          m ^= k;
          arrayOfInt[i4 + 2][1] = m;
          n ^= m;
          arrayOfInt[i4 + 2][2] = n;
          i1 ^= n;
          arrayOfInt[i4 + 2][3] = i1;
          i4 += 3;
          if (i4 >= 13)
            break; 
          i2 ^= i1;
          i3 ^= i2;
        } 
        break;
      case 8:
        k = Pack.littleEndianToInt(paramArrayOfbyte, 0);
        arrayOfInt[0][0] = k;
        m = Pack.littleEndianToInt(paramArrayOfbyte, 4);
        arrayOfInt[0][1] = m;
        n = Pack.littleEndianToInt(paramArrayOfbyte, 8);
        arrayOfInt[0][2] = n;
        i1 = Pack.littleEndianToInt(paramArrayOfbyte, 12);
        arrayOfInt[0][3] = i1;
        i2 = Pack.littleEndianToInt(paramArrayOfbyte, 16);
        arrayOfInt[1][0] = i2;
        i3 = Pack.littleEndianToInt(paramArrayOfbyte, 20);
        arrayOfInt[1][1] = i3;
        i4 = Pack.littleEndianToInt(paramArrayOfbyte, 24);
        arrayOfInt[1][2] = i4;
        i5 = Pack.littleEndianToInt(paramArrayOfbyte, 28);
        arrayOfInt[1][3] = i5;
        b = 2;
        i6 = 1;
        while (true) {
          int i7 = subWord(shift(i5, 8)) ^ i6;
          i6 <<= 1;
          k ^= i7;
          arrayOfInt[b][0] = k;
          m ^= k;
          arrayOfInt[b][1] = m;
          n ^= m;
          arrayOfInt[b][2] = n;
          i1 ^= n;
          arrayOfInt[b][3] = i1;
          if (++b >= 15)
            break; 
          i7 = subWord(i1);
          i2 ^= i7;
          arrayOfInt[b][0] = i2;
          i3 ^= i2;
          arrayOfInt[b][1] = i3;
          i4 ^= i3;
          arrayOfInt[b][2] = i4;
          i5 ^= i4;
          arrayOfInt[b][3] = i5;
          b++;
        } 
        break;
      default:
        throw new IllegalStateException("Should never get here");
    } 
    if (!paramBoolean)
      for (k = 1; k < this.ROUNDS; k++) {
        for (m = 0; m < 4; m++)
          arrayOfInt[k][m] = inv_mcol(arrayOfInt[k][m]); 
      }  
    return arrayOfInt;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    if (paramCipherParameters instanceof KeyParameter) {
      this.WorkingKey = generateWorkingKey(((KeyParameter)paramCipherParameters).getKey(), paramBoolean);
      this.forEncryption = paramBoolean;
      return;
    } 
    throw new IllegalArgumentException("invalid parameter passed to AES init - " + paramCipherParameters.getClass().getName());
  }
  
  public String getAlgorithmName() {
    return "AES";
  }
  
  public int getBlockSize() {
    return 16;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    if (this.WorkingKey == null)
      throw new IllegalStateException("AES engine not initialised"); 
    if (paramInt1 > paramArrayOfbyte1.length - 16)
      throw new DataLengthException("input buffer too short"); 
    if (paramInt2 > paramArrayOfbyte2.length - 16)
      throw new OutputLengthException("output buffer too short"); 
    if (this.forEncryption) {
      encryptBlock(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, this.WorkingKey);
    } else {
      decryptBlock(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, this.WorkingKey);
    } 
    return 16;
  }
  
  public void reset() {}
  
  private void encryptBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, int[][] paramArrayOfint) {
    int i = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 0);
    int j = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 4);
    int k = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 8);
    int m = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 12);
    int n = i ^ paramArrayOfint[0][0];
    int i1 = j ^ paramArrayOfint[0][1];
    int i2 = k ^ paramArrayOfint[0][2];
    byte b = 1;
    int i6;
    for (i6 = m ^ paramArrayOfint[0][3]; b < this.ROUNDS - 1; i6 = mcol(S[i6 & 0xFF] & 0xFF ^ (S[i7 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i8 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i9 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b++][3]) {
      int i7 = mcol(S[n & 0xFF] & 0xFF ^ (S[i1 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i2 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i6 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][0];
      int i8 = mcol(S[i1 & 0xFF] & 0xFF ^ (S[i2 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i6 >> 16 & 0xFF] & 0xFF) << 16 ^ S[n >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][1];
      int i9 = mcol(S[i2 & 0xFF] & 0xFF ^ (S[i6 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[n >> 16 & 0xFF] & 0xFF) << 16 ^ S[i1 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][2];
      i6 = mcol(S[i6 & 0xFF] & 0xFF ^ (S[n >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i1 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i2 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b++][3];
      n = mcol(S[i7 & 0xFF] & 0xFF ^ (S[i8 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i9 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i6 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][0];
      i1 = mcol(S[i8 & 0xFF] & 0xFF ^ (S[i9 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i6 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i7 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][1];
      i2 = mcol(S[i9 & 0xFF] & 0xFF ^ (S[i6 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i7 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i8 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][2];
    } 
    int i3 = mcol(S[n & 0xFF] & 0xFF ^ (S[i1 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i2 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i6 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][0];
    int i4 = mcol(S[i1 & 0xFF] & 0xFF ^ (S[i2 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i6 >> 16 & 0xFF] & 0xFF) << 16 ^ S[n >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][1];
    int i5 = mcol(S[i2 & 0xFF] & 0xFF ^ (S[i6 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[n >> 16 & 0xFF] & 0xFF) << 16 ^ S[i1 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b][2];
    i6 = mcol(S[i6 & 0xFF] & 0xFF ^ (S[n >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i1 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i2 >> 24 & 0xFF] << 24) ^ paramArrayOfint[b++][3];
    i = S[i3 & 0xFF] & 0xFF ^ (S[i4 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i5 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i6 >> 24 & 0xFF] << 24 ^ paramArrayOfint[b][0];
    j = S[i4 & 0xFF] & 0xFF ^ (S[i5 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i6 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i3 >> 24 & 0xFF] << 24 ^ paramArrayOfint[b][1];
    k = S[i5 & 0xFF] & 0xFF ^ (S[i6 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i3 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i4 >> 24 & 0xFF] << 24 ^ paramArrayOfint[b][2];
    m = S[i6 & 0xFF] & 0xFF ^ (S[i3 >> 8 & 0xFF] & 0xFF) << 8 ^ (S[i4 >> 16 & 0xFF] & 0xFF) << 16 ^ S[i5 >> 24 & 0xFF] << 24 ^ paramArrayOfint[b][3];
    Pack.intToLittleEndian(i, paramArrayOfbyte2, paramInt2 + 0);
    Pack.intToLittleEndian(j, paramArrayOfbyte2, paramInt2 + 4);
    Pack.intToLittleEndian(k, paramArrayOfbyte2, paramInt2 + 8);
    Pack.intToLittleEndian(m, paramArrayOfbyte2, paramInt2 + 12);
  }
  
  private void decryptBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, int[][] paramArrayOfint) {
    int i = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 0);
    int j = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 4);
    int k = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 8);
    int m = Pack.littleEndianToInt(paramArrayOfbyte1, paramInt1 + 12);
    int n = i ^ paramArrayOfint[this.ROUNDS][0];
    int i1 = j ^ paramArrayOfint[this.ROUNDS][1];
    int i2 = k ^ paramArrayOfint[this.ROUNDS][2];
    int i3 = this.ROUNDS - 1;
    int i7;
    for (i7 = m ^ paramArrayOfint[this.ROUNDS][3]; i3 > 1; i7 = inv_mcol(Si[i7 & 0xFF] & 0xFF ^ (Si[i10 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i9 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i8 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3--][3]) {
      int i8 = inv_mcol(Si[n & 0xFF] & 0xFF ^ (Si[i7 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i2 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i1 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][0];
      int i9 = inv_mcol(Si[i1 & 0xFF] & 0xFF ^ (Si[n >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i7 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i2 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][1];
      int i10 = inv_mcol(Si[i2 & 0xFF] & 0xFF ^ (Si[i1 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[n >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i7 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][2];
      i7 = inv_mcol(Si[i7 & 0xFF] & 0xFF ^ (Si[i2 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i1 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[n >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3--][3];
      n = inv_mcol(Si[i8 & 0xFF] & 0xFF ^ (Si[i7 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i10 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i9 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][0];
      i1 = inv_mcol(Si[i9 & 0xFF] & 0xFF ^ (Si[i8 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i7 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i10 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][1];
      i2 = inv_mcol(Si[i10 & 0xFF] & 0xFF ^ (Si[i9 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i8 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i7 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][2];
    } 
    int i4 = inv_mcol(Si[n & 0xFF] & 0xFF ^ (Si[i7 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i2 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i1 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][0];
    int i5 = inv_mcol(Si[i1 & 0xFF] & 0xFF ^ (Si[n >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i7 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i2 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][1];
    int i6 = inv_mcol(Si[i2 & 0xFF] & 0xFF ^ (Si[i1 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[n >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i7 >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][2];
    i7 = inv_mcol(Si[i7 & 0xFF] & 0xFF ^ (Si[i2 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i1 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[n >> 24 & 0xFF] << 24) ^ paramArrayOfint[i3][3];
    i = Si[i4 & 0xFF] & 0xFF ^ (Si[i7 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i6 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i5 >> 24 & 0xFF] << 24 ^ paramArrayOfint[0][0];
    j = Si[i5 & 0xFF] & 0xFF ^ (Si[i4 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i7 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i6 >> 24 & 0xFF] << 24 ^ paramArrayOfint[0][1];
    k = Si[i6 & 0xFF] & 0xFF ^ (Si[i5 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i4 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i7 >> 24 & 0xFF] << 24 ^ paramArrayOfint[0][2];
    m = Si[i7 & 0xFF] & 0xFF ^ (Si[i6 >> 8 & 0xFF] & 0xFF) << 8 ^ (Si[i5 >> 16 & 0xFF] & 0xFF) << 16 ^ Si[i4 >> 24 & 0xFF] << 24 ^ paramArrayOfint[0][3];
    Pack.intToLittleEndian(i, paramArrayOfbyte2, paramInt2 + 0);
    Pack.intToLittleEndian(j, paramArrayOfbyte2, paramInt2 + 4);
    Pack.intToLittleEndian(k, paramArrayOfbyte2, paramInt2 + 8);
    Pack.intToLittleEndian(m, paramArrayOfbyte2, paramInt2 + 12);
  }
}
