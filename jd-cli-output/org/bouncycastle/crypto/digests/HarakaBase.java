package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Digest;

public abstract class HarakaBase implements Digest {
  protected static final int DIGEST_SIZE = 32;
  
  private static final byte[][] S = new byte[][] { 
      { 
        99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 
        103, 43, -2, -41, -85, 118 }, { 
        -54, -126, -55, 125, -6, 89, 71, -16, -83, -44, 
        -94, -81, -100, -92, 114, -64 }, { 
        -73, -3, -109, 38, 54, 63, -9, -52, 52, -91, 
        -27, -15, 113, -40, 49, 21 }, { 
        4, -57, 35, -61, 24, -106, 5, -102, 7, 18, 
        Byte.MIN_VALUE, -30, -21, 39, -78, 117 }, { 
        9, -125, 44, 26, 27, 110, 90, -96, 82, 59, 
        -42, -77, 41, -29, 47, -124 }, { 
        83, -47, 0, -19, 32, -4, -79, 91, 106, -53, 
        -66, 57, 74, 76, 88, -49 }, { 
        -48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 
        2, Byte.MAX_VALUE, 80, 60, -97, -88 }, { 
        81, -93, 64, -113, -110, -99, 56, -11, -68, -74, 
        -38, 33, 16, -1, -13, -46 }, { 
        -51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 
        126, 61, 100, 93, 25, 115 }, { 
        96, -127, 79, -36, 34, 42, -112, -120, 70, -18, 
        -72, 20, -34, 94, 11, -37 }, 
      { 
        -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, 
        -84, 98, -111, -107, -28, 121 }, { 
        -25, -56, 55, 109, -115, -43, 78, -87, 108, 86, 
        -12, -22, 101, 122, -82, 8 }, { 
        -70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 
        116, 31, 75, -67, -117, -118 }, { 
        112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 
        87, -71, -122, -63, 29, -98 }, { 
        -31, -8, -104, 17, 105, -39, -114, -108, -101, 30, 
        -121, -23, -50, 85, 40, -33 }, { 
        -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 
        45, 15, -80, 84, -69, 22 } };
  
  static byte sBox(byte paramByte) {
    return S[(paramByte & 0xFF) >>> 4][paramByte & 0xF];
  }
  
  static byte[] subBytes(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[paramArrayOfbyte.length];
    arrayOfByte[0] = sBox(paramArrayOfbyte[0]);
    arrayOfByte[1] = sBox(paramArrayOfbyte[1]);
    arrayOfByte[2] = sBox(paramArrayOfbyte[2]);
    arrayOfByte[3] = sBox(paramArrayOfbyte[3]);
    arrayOfByte[4] = sBox(paramArrayOfbyte[4]);
    arrayOfByte[5] = sBox(paramArrayOfbyte[5]);
    arrayOfByte[6] = sBox(paramArrayOfbyte[6]);
    arrayOfByte[7] = sBox(paramArrayOfbyte[7]);
    arrayOfByte[8] = sBox(paramArrayOfbyte[8]);
    arrayOfByte[9] = sBox(paramArrayOfbyte[9]);
    arrayOfByte[10] = sBox(paramArrayOfbyte[10]);
    arrayOfByte[11] = sBox(paramArrayOfbyte[11]);
    arrayOfByte[12] = sBox(paramArrayOfbyte[12]);
    arrayOfByte[13] = sBox(paramArrayOfbyte[13]);
    arrayOfByte[14] = sBox(paramArrayOfbyte[14]);
    arrayOfByte[15] = sBox(paramArrayOfbyte[15]);
    return arrayOfByte;
  }
  
  static byte[] shiftRows(byte[] paramArrayOfbyte) {
    return new byte[] { 
        paramArrayOfbyte[0], paramArrayOfbyte[5], paramArrayOfbyte[10], paramArrayOfbyte[15], paramArrayOfbyte[4], paramArrayOfbyte[9], paramArrayOfbyte[14], paramArrayOfbyte[3], paramArrayOfbyte[8], paramArrayOfbyte[13], 
        paramArrayOfbyte[2], paramArrayOfbyte[7], paramArrayOfbyte[12], paramArrayOfbyte[1], paramArrayOfbyte[6], paramArrayOfbyte[11] };
  }
  
  static byte[] aesEnc(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    paramArrayOfbyte1 = subBytes(paramArrayOfbyte1);
    paramArrayOfbyte1 = shiftRows(paramArrayOfbyte1);
    paramArrayOfbyte1 = mixColumns(paramArrayOfbyte1);
    xorReverse(paramArrayOfbyte1, paramArrayOfbyte2);
    return paramArrayOfbyte1;
  }
  
  static byte xTime(byte paramByte) {
    return (paramByte >>> 7 > 0) ? (byte)((paramByte << 1 ^ 0x1B) & 0xFF) : (byte)(paramByte << 1 & 0xFF);
  }
  
  static void xorReverse(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    paramArrayOfbyte1[0] = (byte)(paramArrayOfbyte1[0] ^ paramArrayOfbyte2[15]);
    paramArrayOfbyte1[1] = (byte)(paramArrayOfbyte1[1] ^ paramArrayOfbyte2[14]);
    paramArrayOfbyte1[2] = (byte)(paramArrayOfbyte1[2] ^ paramArrayOfbyte2[13]);
    paramArrayOfbyte1[3] = (byte)(paramArrayOfbyte1[3] ^ paramArrayOfbyte2[12]);
    paramArrayOfbyte1[4] = (byte)(paramArrayOfbyte1[4] ^ paramArrayOfbyte2[11]);
    paramArrayOfbyte1[5] = (byte)(paramArrayOfbyte1[5] ^ paramArrayOfbyte2[10]);
    paramArrayOfbyte1[6] = (byte)(paramArrayOfbyte1[6] ^ paramArrayOfbyte2[9]);
    paramArrayOfbyte1[7] = (byte)(paramArrayOfbyte1[7] ^ paramArrayOfbyte2[8]);
    paramArrayOfbyte1[8] = (byte)(paramArrayOfbyte1[8] ^ paramArrayOfbyte2[7]);
    paramArrayOfbyte1[9] = (byte)(paramArrayOfbyte1[9] ^ paramArrayOfbyte2[6]);
    paramArrayOfbyte1[10] = (byte)(paramArrayOfbyte1[10] ^ paramArrayOfbyte2[5]);
    paramArrayOfbyte1[11] = (byte)(paramArrayOfbyte1[11] ^ paramArrayOfbyte2[4]);
    paramArrayOfbyte1[12] = (byte)(paramArrayOfbyte1[12] ^ paramArrayOfbyte2[3]);
    paramArrayOfbyte1[13] = (byte)(paramArrayOfbyte1[13] ^ paramArrayOfbyte2[2]);
    paramArrayOfbyte1[14] = (byte)(paramArrayOfbyte1[14] ^ paramArrayOfbyte2[1]);
    paramArrayOfbyte1[15] = (byte)(paramArrayOfbyte1[15] ^ paramArrayOfbyte2[0]);
  }
  
  static byte[] xor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    byte[] arrayOfByte = new byte[16];
    for (byte b = 0; b < arrayOfByte.length; b++)
      arrayOfByte[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[paramInt++]); 
    return arrayOfByte;
  }
  
  private static byte[] mixColumns(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[paramArrayOfbyte.length];
    byte b1 = 0;
    for (byte b2 = 0; b2 < 4; b2++) {
      arrayOfByte[b1++] = (byte)(xTime(paramArrayOfbyte[4 * b2]) ^ xTime(paramArrayOfbyte[4 * b2 + 1]) ^ paramArrayOfbyte[4 * b2 + 1] ^ paramArrayOfbyte[4 * b2 + 2] ^ paramArrayOfbyte[4 * b2 + 3]);
      arrayOfByte[b1++] = (byte)(paramArrayOfbyte[4 * b2] ^ xTime(paramArrayOfbyte[4 * b2 + 1]) ^ xTime(paramArrayOfbyte[4 * b2 + 2]) ^ paramArrayOfbyte[4 * b2 + 2] ^ paramArrayOfbyte[4 * b2 + 3]);
      arrayOfByte[b1++] = (byte)(paramArrayOfbyte[4 * b2] ^ paramArrayOfbyte[4 * b2 + 1] ^ xTime(paramArrayOfbyte[4 * b2 + 2]) ^ xTime(paramArrayOfbyte[4 * b2 + 3]) ^ paramArrayOfbyte[4 * b2 + 3]);
      arrayOfByte[b1++] = (byte)(xTime(paramArrayOfbyte[4 * b2]) ^ paramArrayOfbyte[4 * b2] ^ paramArrayOfbyte[4 * b2 + 1] ^ paramArrayOfbyte[4 * b2 + 2] ^ xTime(paramArrayOfbyte[4 * b2 + 3]));
    } 
    return arrayOfByte;
  }
  
  public int getDigestSize() {
    return 32;
  }
}
