package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

public class DSTU7564Digest implements ExtendedDigest, Memoable {
  private static final int NB_512 = 8;
  
  private static final int NB_1024 = 16;
  
  private static final int NR_512 = 10;
  
  private static final int NR_1024 = 14;
  
  private int hashSize;
  
  private int blockSize;
  
  private int columns;
  
  private int rounds;
  
  private long[] state;
  
  private long[] tempState1;
  
  private long[] tempState2;
  
  private long inputBlocks;
  
  private int bufOff;
  
  private byte[] buf;
  
  private static final byte[] S0 = new byte[] { 
      -88, 67, 95, 6, 107, 117, 108, 89, 113, -33, 
      -121, -107, 23, -16, -40, 9, 109, -13, 29, -53, 
      -55, 77, 44, -81, 121, -32, -105, -3, 111, 75, 
      69, 57, 62, -35, -93, 79, -76, -74, -102, 14, 
      31, -65, 21, -31, 73, -46, -109, -58, -110, 114, 
      -98, 97, -47, 99, -6, -18, -12, 25, -43, -83, 
      88, -92, -69, -95, -36, -14, -125, 55, 66, -28, 
      122, 50, -100, -52, -85, 74, -113, 110, 4, 39, 
      46, -25, -30, 90, -106, 22, 35, 43, -62, 101, 
      102, 15, -68, -87, 71, 65, 52, 72, -4, -73, 
      106, -120, -91, 83, -122, -7, 91, -37, 56, 123, 
      -61, 30, 34, 51, 36, 40, 54, -57, -78, 59, 
      -114, 119, -70, -11, 20, -97, 8, 85, -101, 76, 
      -2, 96, 92, -38, 24, 70, -51, 125, 33, -80, 
      63, 27, -119, -1, -21, -124, 105, 58, -99, -41, 
      -45, 112, 103, 64, -75, -34, 93, 48, -111, -79, 
      120, 17, 1, -27, 0, 104, -104, -96, -59, 2, 
      -90, 116, 45, 11, -94, 118, -77, -66, -50, -67, 
      -82, -23, -118, 49, 28, -20, -15, -103, -108, -86, 
      -10, 38, 47, -17, -24, -116, 53, 3, -44, Byte.MAX_VALUE, 
      -5, 5, -63, 94, -112, 32, 61, -126, -9, -22, 
      10, 13, 126, -8, 80, 26, -60, 7, 87, -72, 
      60, 98, -29, -56, -84, 82, 100, 16, -48, -39, 
      19, 12, 18, 41, 81, -71, -49, -42, 115, -115, 
      -127, 84, -64, -19, 78, 68, -89, 42, -123, 37, 
      -26, -54, 124, -117, 86, Byte.MIN_VALUE };
  
  private static final byte[] S1 = new byte[] { 
      -50, -69, -21, -110, -22, -53, 19, -63, -23, 58, 
      -42, -78, -46, -112, 23, -8, 66, 21, 86, -76, 
      101, 28, -120, 67, -59, 92, 54, -70, -11, 87, 
      103, -115, 49, -10, 100, 88, -98, -12, 34, -86, 
      117, 15, 2, -79, -33, 109, 115, 77, 124, 38, 
      46, -9, 8, 93, 68, 62, -97, 20, -56, -82, 
      84, 16, -40, -68, 26, 107, 105, -13, -67, 51, 
      -85, -6, -47, -101, 104, 78, 22, -107, -111, -18, 
      76, 99, -114, 91, -52, 60, 25, -95, -127, 73, 
      123, -39, 111, 55, 96, -54, -25, 43, 72, -3, 
      -106, 69, -4, 65, 18, 13, 121, -27, -119, -116, 
      -29, 32, 48, -36, -73, 108, 74, -75, 63, -105, 
      -44, 98, 45, 6, -92, -91, -125, 95, 42, -38, 
      -55, 0, 126, -94, 85, -65, 17, -43, -100, -49, 
      14, 10, 61, 81, 125, -109, 27, -2, -60, 71, 
      9, -122, 11, -113, -99, 106, 7, -71, -80, -104, 
      24, 50, 113, 75, -17, 59, 112, -96, -28, 64, 
      -1, -61, -87, -26, 120, -7, -117, 70, Byte.MIN_VALUE, 30, 
      56, -31, -72, -88, -32, 12, 35, 118, 29, 37, 
      36, 5, -15, 110, -108, 40, -102, -124, -24, -93, 
      79, 119, -45, -123, -30, 82, -14, -126, 80, 122, 
      47, 116, 83, -77, 97, -81, 57, 53, -34, -51, 
      31, -103, -84, -83, 114, 44, -35, -48, -121, -66, 
      94, -90, -20, 4, -58, 3, 52, -5, -37, 89, 
      -74, -62, 1, -16, 90, -19, -89, 102, 33, Byte.MAX_VALUE, 
      -118, 39, -57, -64, 41, -41 };
  
  private static final byte[] S2 = new byte[] { 
      -109, -39, -102, -75, -104, 34, 69, -4, -70, 106, 
      -33, 2, -97, -36, 81, 89, 74, 23, 43, -62, 
      -108, -12, -69, -93, 98, -28, 113, -44, -51, 112, 
      22, -31, 73, 60, -64, -40, 92, -101, -83, -123, 
      83, -95, 122, -56, 45, -32, -47, 114, -90, 44, 
      -60, -29, 118, 120, -73, -76, 9, 59, 14, 65, 
      76, -34, -78, -112, 37, -91, -41, 3, 17, 0, 
      -61, 46, -110, -17, 78, 18, -99, 125, -53, 53, 
      16, -43, 79, -98, 77, -87, 85, -58, -48, 123, 
      24, -105, -45, 54, -26, 72, 86, -127, -113, 119, 
      -52, -100, -71, -30, -84, -72, 47, 21, -92, 124, 
      -38, 56, 30, 11, 5, -42, 20, 110, 108, 126, 
      102, -3, -79, -27, 96, -81, 94, 51, -121, -55, 
      -16, 93, 109, 63, -120, -115, -57, -9, 29, -23, 
      -20, -19, Byte.MIN_VALUE, 41, 39, -49, -103, -88, 80, 15, 
      55, 36, 40, 48, -107, -46, 62, 91, 64, -125, 
      -77, 105, 87, 31, 7, 28, -118, -68, 32, -21, 
      -50, -114, -85, -18, 49, -94, 115, -7, -54, 58, 
      26, -5, 13, -63, -2, -6, -14, 111, -67, -106, 
      -35, 67, 82, -74, 8, -13, -82, -66, 25, -119, 
      50, 38, -80, -22, 75, 100, -124, -126, 107, -11, 
      121, -65, 1, 95, 117, 99, 27, 35, 61, 104, 
      42, 101, -24, -111, -10, -1, 19, 88, -15, 71, 
      10, Byte.MAX_VALUE, -59, -89, -25, 97, 90, 6, 70, 68, 
      66, 4, -96, -37, 57, -122, 84, -86, -116, 52, 
      33, -117, -8, 12, 116, 103 };
  
  private static final byte[] S3 = new byte[] { 
      104, -115, -54, 77, 115, 75, 78, 42, -44, 82, 
      38, -77, 84, 30, 25, 31, 34, 3, 70, 61, 
      45, 74, 83, -125, 19, -118, -73, -43, 37, 121, 
      -11, -67, 88, 47, 13, 2, -19, 81, -98, 17, 
      -14, 62, 85, 94, -47, 22, 60, 102, 112, 93, 
      -13, 69, 64, -52, -24, -108, 86, 8, -50, 26, 
      58, -46, -31, -33, -75, 56, 110, 14, -27, -12, 
      -7, -122, -23, 79, -42, -123, 35, -49, 50, -103, 
      49, 20, -82, -18, -56, 72, -45, 48, -95, -110, 
      65, -79, 24, -60, 44, 113, 114, 68, 21, -3, 
      55, -66, 95, -86, -101, -120, -40, -85, -119, -100, 
      -6, 96, -22, -68, 98, 12, 36, -90, -88, -20, 
      103, 32, -37, 124, 40, -35, -84, 91, 52, 126, 
      16, -15, 123, -113, 99, -96, 5, -102, 67, 119, 
      33, -65, 39, 9, -61, -97, -74, -41, 41, -62, 
      -21, -64, -92, -117, -116, 29, -5, -1, -63, -78, 
      -105, 46, -8, 101, -10, 117, 7, 4, 73, 51, 
      -28, -39, -71, -48, 66, -57, 108, -112, 0, -114, 
      111, 80, 1, -59, -38, 71, 63, -51, 105, -94, 
      -30, 122, -89, -58, -109, 15, 10, 6, -26, 43, 
      -106, -93, 28, -81, 106, 18, -124, 57, -25, -80, 
      -126, -9, -2, -99, -121, 92, -127, 53, -34, -76, 
      -91, -4, Byte.MIN_VALUE, -17, -53, -69, 107, 118, -70, 90, 
      125, 120, 11, -107, -29, -83, 116, -104, 59, 54, 
      100, 109, -36, -16, 89, -87, 76, 23, Byte.MAX_VALUE, -111, 
      -72, -55, 87, 27, -32, 97 };
  
  public DSTU7564Digest(DSTU7564Digest paramDSTU7564Digest) {
    copyIn(paramDSTU7564Digest);
  }
  
  private void copyIn(DSTU7564Digest paramDSTU7564Digest) {
    this.hashSize = paramDSTU7564Digest.hashSize;
    this.blockSize = paramDSTU7564Digest.blockSize;
    this.rounds = paramDSTU7564Digest.rounds;
    if (this.columns > 0 && this.columns == paramDSTU7564Digest.columns) {
      System.arraycopy(paramDSTU7564Digest.state, 0, this.state, 0, this.columns);
      System.arraycopy(paramDSTU7564Digest.buf, 0, this.buf, 0, this.blockSize);
    } else {
      this.columns = paramDSTU7564Digest.columns;
      this.state = Arrays.clone(paramDSTU7564Digest.state);
      this.tempState1 = new long[this.columns];
      this.tempState2 = new long[this.columns];
      this.buf = Arrays.clone(paramDSTU7564Digest.buf);
    } 
    this.inputBlocks = paramDSTU7564Digest.inputBlocks;
    this.bufOff = paramDSTU7564Digest.bufOff;
  }
  
  public DSTU7564Digest(int paramInt) {
    if (paramInt == 256 || paramInt == 384 || paramInt == 512) {
      this.hashSize = paramInt >>> 3;
    } else {
      throw new IllegalArgumentException("Hash size is not recommended. Use 256/384/512 instead");
    } 
    if (paramInt > 256) {
      this.columns = 16;
      this.rounds = 14;
    } else {
      this.columns = 8;
      this.rounds = 10;
    } 
    this.blockSize = this.columns << 3;
    this.state = new long[this.columns];
    this.state[0] = this.blockSize;
    this.tempState1 = new long[this.columns];
    this.tempState2 = new long[this.columns];
    this.buf = new byte[this.blockSize];
  }
  
  public String getAlgorithmName() {
    return "DSTU7564";
  }
  
  public int getDigestSize() {
    return this.hashSize;
  }
  
  public int getByteLength() {
    return this.blockSize;
  }
  
  public void update(byte paramByte) {
    this.buf[this.bufOff++] = paramByte;
    if (this.bufOff == this.blockSize) {
      processBlock(this.buf, 0);
      this.bufOff = 0;
      this.inputBlocks++;
    } 
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    while (this.bufOff != 0 && paramInt2 > 0) {
      update(paramArrayOfbyte[paramInt1++]);
      paramInt2--;
    } 
    if (paramInt2 > 0) {
      while (paramInt2 >= this.blockSize) {
        processBlock(paramArrayOfbyte, paramInt1);
        paramInt1 += this.blockSize;
        paramInt2 -= this.blockSize;
        this.inputBlocks++;
      } 
      while (paramInt2 > 0) {
        update(paramArrayOfbyte[paramInt1++]);
        paramInt2--;
      } 
    } 
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    int i = this.bufOff;
    this.buf[this.bufOff++] = Byte.MIN_VALUE;
    int j = this.blockSize - 12;
    if (this.bufOff > j) {
      while (this.bufOff < this.blockSize)
        this.buf[this.bufOff++] = 0; 
      this.bufOff = 0;
      processBlock(this.buf, 0);
    } 
    while (this.bufOff < j)
      this.buf[this.bufOff++] = 0; 
    long l = (this.inputBlocks & 0xFFFFFFFFL) * this.blockSize + i << 3L;
    Pack.intToLittleEndian((int)l, this.buf, this.bufOff);
    this.bufOff += 4;
    l >>>= 32L;
    l += (this.inputBlocks >>> 32L) * this.blockSize << 3L;
    Pack.longToLittleEndian(l, this.buf, this.bufOff);
    processBlock(this.buf, 0);
    System.arraycopy(this.state, 0, this.tempState1, 0, this.columns);
    P(this.tempState1);
    for (i = 0; i < this.columns; i++)
      this.state[i] = this.state[i] ^ this.tempState1[i]; 
    i = this.hashSize >>> 3;
    for (j = this.columns - i; j < this.columns; j++) {
      Pack.longToLittleEndian(this.state[j], paramArrayOfbyte, paramInt);
      paramInt += 8;
    } 
    reset();
    return this.hashSize;
  }
  
  public void reset() {
    Arrays.fill(this.state, 0L);
    this.state[0] = this.blockSize;
    this.inputBlocks = 0L;
    this.bufOff = 0;
  }
  
  private void processBlock(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramInt;
    byte b;
    for (b = 0; b < this.columns; b++) {
      long l = Pack.littleEndianToLong(paramArrayOfbyte, i);
      i += 8;
      this.tempState1[b] = this.state[b] ^ l;
      this.tempState2[b] = l;
    } 
    P(this.tempState1);
    Q(this.tempState2);
    for (b = 0; b < this.columns; b++)
      this.state[b] = this.state[b] ^ this.tempState1[b] ^ this.tempState2[b]; 
  }
  
  private void P(long[] paramArrayOflong) {
    for (byte b = 0; b < this.rounds; b++) {
      long l = b;
      for (byte b1 = 0; b1 < this.columns; b1++) {
        paramArrayOflong[b1] = paramArrayOflong[b1] ^ l;
        l += 16L;
      } 
      shiftRows(paramArrayOflong);
      subBytes(paramArrayOflong);
      mixColumns(paramArrayOflong);
    } 
  }
  
  private void Q(long[] paramArrayOflong) {
    for (byte b = 0; b < this.rounds; b++) {
      long l = (this.columns - 1 << 4 ^ b) << 56L | 0xF0F0F0F0F0F0F3L;
      for (byte b1 = 0; b1 < this.columns; b1++) {
        paramArrayOflong[b1] = paramArrayOflong[b1] + l;
        l -= 1152921504606846976L;
      } 
      shiftRows(paramArrayOflong);
      subBytes(paramArrayOflong);
      mixColumns(paramArrayOflong);
    } 
  }
  
  private static long mixColumn(long paramLong) {
    long l1 = (paramLong & 0x7F7F7F7F7F7F7F7FL) << 1L ^ ((paramLong & 0x8080808080808080L) >>> 7L) * 29L;
    long l2 = rotate(8, paramLong) ^ paramLong;
    l2 ^= rotate(16, l2);
    l2 ^= rotate(48, paramLong);
    long l3 = l2 ^ paramLong ^ l1;
    l3 = (l3 & 0x3F3F3F3F3F3F3F3FL) << 2L ^ ((l3 & 0x8080808080808080L) >>> 6L) * 29L ^ ((l3 & 0x4040404040404040L) >>> 6L) * 29L;
    return l2 ^ rotate(32, l3) ^ rotate(40, l1) ^ rotate(48, l1);
  }
  
  private void mixColumns(long[] paramArrayOflong) {
    for (byte b = 0; b < this.columns; b++)
      paramArrayOflong[b] = mixColumn(paramArrayOflong[b]); 
  }
  
  private static long rotate(int paramInt, long paramLong) {
    return paramLong >>> paramInt | paramLong << -paramInt;
  }
  
  private void shiftRows(long[] paramArrayOflong) {
    long l1;
    long l2;
    long l3;
    long l4;
    long l5;
    long l6;
    long l7;
    long l8;
    long l9;
    long l10;
    long l11;
    long l12;
    long l13;
    long l14;
    long l15;
    long l16;
    long l17;
    switch (this.columns) {
      case 8:
        l1 = paramArrayOflong[0];
        l2 = paramArrayOflong[1];
        l3 = paramArrayOflong[2];
        l4 = paramArrayOflong[3];
        l5 = paramArrayOflong[4];
        l6 = paramArrayOflong[5];
        l7 = paramArrayOflong[6];
        l8 = paramArrayOflong[7];
        l9 = (l1 ^ l5) & 0xFFFFFFFF00000000L;
        l1 ^= l9;
        l5 ^= l9;
        l9 = (l2 ^ l6) & 0xFFFFFFFF000000L;
        l2 ^= l9;
        l6 ^= l9;
        l9 = (l3 ^ l7) & 0xFFFFFFFF0000L;
        l3 ^= l9;
        l7 ^= l9;
        l9 = (l4 ^ l8) & 0xFFFFFFFF00L;
        l4 ^= l9;
        l8 ^= l9;
        l9 = (l1 ^ l3) & 0xFFFF0000FFFF0000L;
        l1 ^= l9;
        l3 ^= l9;
        l9 = (l2 ^ l4) & 0xFFFF0000FFFF00L;
        l2 ^= l9;
        l4 ^= l9;
        l9 = (l5 ^ l7) & 0xFFFF0000FFFF0000L;
        l5 ^= l9;
        l7 ^= l9;
        l9 = (l6 ^ l8) & 0xFFFF0000FFFF00L;
        l6 ^= l9;
        l8 ^= l9;
        l9 = (l1 ^ l2) & 0xFF00FF00FF00FF00L;
        l1 ^= l9;
        l2 ^= l9;
        l9 = (l3 ^ l4) & 0xFF00FF00FF00FF00L;
        l3 ^= l9;
        l4 ^= l9;
        l9 = (l5 ^ l6) & 0xFF00FF00FF00FF00L;
        l5 ^= l9;
        l6 ^= l9;
        l9 = (l7 ^ l8) & 0xFF00FF00FF00FF00L;
        l7 ^= l9;
        l8 ^= l9;
        paramArrayOflong[0] = l1;
        paramArrayOflong[1] = l2;
        paramArrayOflong[2] = l3;
        paramArrayOflong[3] = l4;
        paramArrayOflong[4] = l5;
        paramArrayOflong[5] = l6;
        paramArrayOflong[6] = l7;
        paramArrayOflong[7] = l8;
        return;
      case 16:
        l1 = paramArrayOflong[0];
        l2 = paramArrayOflong[1];
        l3 = paramArrayOflong[2];
        l4 = paramArrayOflong[3];
        l5 = paramArrayOflong[4];
        l6 = paramArrayOflong[5];
        l7 = paramArrayOflong[6];
        l8 = paramArrayOflong[7];
        l9 = paramArrayOflong[8];
        l10 = paramArrayOflong[9];
        l11 = paramArrayOflong[10];
        l12 = paramArrayOflong[11];
        l13 = paramArrayOflong[12];
        l14 = paramArrayOflong[13];
        l15 = paramArrayOflong[14];
        l16 = paramArrayOflong[15];
        l17 = (l1 ^ l9) & 0xFF00000000000000L;
        l1 ^= l17;
        l9 ^= l17;
        l17 = (l2 ^ l10) & 0xFF00000000000000L;
        l2 ^= l17;
        l10 ^= l17;
        l17 = (l3 ^ l11) & 0xFFFF000000000000L;
        l3 ^= l17;
        l11 ^= l17;
        l17 = (l4 ^ l12) & 0xFFFFFF0000000000L;
        l4 ^= l17;
        l12 ^= l17;
        l17 = (l5 ^ l13) & 0xFFFFFFFF00000000L;
        l5 ^= l17;
        l13 ^= l17;
        l17 = (l6 ^ l14) & 0xFFFFFFFF000000L;
        l6 ^= l17;
        l14 ^= l17;
        l17 = (l7 ^ l15) & 0xFFFFFFFFFF0000L;
        l7 ^= l17;
        l15 ^= l17;
        l17 = (l8 ^ l16) & 0xFFFFFFFFFFFF00L;
        l8 ^= l17;
        l16 ^= l17;
        l17 = (l1 ^ l5) & 0xFFFFFF00000000L;
        l1 ^= l17;
        l5 ^= l17;
        l17 = (l2 ^ l6) & 0xFFFFFFFFFF000000L;
        l2 ^= l17;
        l6 ^= l17;
        l17 = (l3 ^ l7) & 0xFF00FFFFFFFF0000L;
        l3 ^= l17;
        l7 ^= l17;
        l17 = (l4 ^ l8) & 0xFF0000FFFFFFFF00L;
        l4 ^= l17;
        l8 ^= l17;
        l17 = (l9 ^ l13) & 0xFFFFFF00000000L;
        l9 ^= l17;
        l13 ^= l17;
        l17 = (l10 ^ l14) & 0xFFFFFFFFFF000000L;
        l10 ^= l17;
        l14 ^= l17;
        l17 = (l11 ^ l15) & 0xFF00FFFFFFFF0000L;
        l11 ^= l17;
        l15 ^= l17;
        l17 = (l12 ^ l16) & 0xFF0000FFFFFFFF00L;
        l12 ^= l17;
        l16 ^= l17;
        l17 = (l1 ^ l3) & 0xFFFF0000FFFF0000L;
        l1 ^= l17;
        l3 ^= l17;
        l17 = (l2 ^ l4) & 0xFFFF0000FFFF00L;
        l2 ^= l17;
        l4 ^= l17;
        l17 = (l5 ^ l7) & 0xFFFF0000FFFF0000L;
        l5 ^= l17;
        l7 ^= l17;
        l17 = (l6 ^ l8) & 0xFFFF0000FFFF00L;
        l6 ^= l17;
        l8 ^= l17;
        l17 = (l9 ^ l11) & 0xFFFF0000FFFF0000L;
        l9 ^= l17;
        l11 ^= l17;
        l17 = (l10 ^ l12) & 0xFFFF0000FFFF00L;
        l10 ^= l17;
        l12 ^= l17;
        l17 = (l13 ^ l15) & 0xFFFF0000FFFF0000L;
        l13 ^= l17;
        l15 ^= l17;
        l17 = (l14 ^ l16) & 0xFFFF0000FFFF00L;
        l14 ^= l17;
        l16 ^= l17;
        l17 = (l1 ^ l2) & 0xFF00FF00FF00FF00L;
        l1 ^= l17;
        l2 ^= l17;
        l17 = (l3 ^ l4) & 0xFF00FF00FF00FF00L;
        l3 ^= l17;
        l4 ^= l17;
        l17 = (l5 ^ l6) & 0xFF00FF00FF00FF00L;
        l5 ^= l17;
        l6 ^= l17;
        l17 = (l7 ^ l8) & 0xFF00FF00FF00FF00L;
        l7 ^= l17;
        l8 ^= l17;
        l17 = (l9 ^ l10) & 0xFF00FF00FF00FF00L;
        l9 ^= l17;
        l10 ^= l17;
        l17 = (l11 ^ l12) & 0xFF00FF00FF00FF00L;
        l11 ^= l17;
        l12 ^= l17;
        l17 = (l13 ^ l14) & 0xFF00FF00FF00FF00L;
        l13 ^= l17;
        l14 ^= l17;
        l17 = (l15 ^ l16) & 0xFF00FF00FF00FF00L;
        l15 ^= l17;
        l16 ^= l17;
        paramArrayOflong[0] = l1;
        paramArrayOflong[1] = l2;
        paramArrayOflong[2] = l3;
        paramArrayOflong[3] = l4;
        paramArrayOflong[4] = l5;
        paramArrayOflong[5] = l6;
        paramArrayOflong[6] = l7;
        paramArrayOflong[7] = l8;
        paramArrayOflong[8] = l9;
        paramArrayOflong[9] = l10;
        paramArrayOflong[10] = l11;
        paramArrayOflong[11] = l12;
        paramArrayOflong[12] = l13;
        paramArrayOflong[13] = l14;
        paramArrayOflong[14] = l15;
        paramArrayOflong[15] = l16;
        return;
    } 
    throw new IllegalStateException("unsupported state size: only 512/1024 are allowed");
  }
  
  private void subBytes(long[] paramArrayOflong) {
    for (byte b = 0; b < this.columns; b++) {
      long l = paramArrayOflong[b];
      int i = (int)l;
      int j = (int)(l >>> 32L);
      byte b1 = S0[i & 0xFF];
      byte b2 = S1[i >>> 8 & 0xFF];
      byte b3 = S2[i >>> 16 & 0xFF];
      byte b4 = S3[i >>> 24];
      i = b1 & 0xFF | (b2 & 0xFF) << 8 | (b3 & 0xFF) << 16 | b4 << 24;
      byte b5 = S0[j & 0xFF];
      byte b6 = S1[j >>> 8 & 0xFF];
      byte b7 = S2[j >>> 16 & 0xFF];
      byte b8 = S3[j >>> 24];
      j = b5 & 0xFF | (b6 & 0xFF) << 8 | (b7 & 0xFF) << 16 | b8 << 24;
      paramArrayOflong[b] = i & 0xFFFFFFFFL | j << 32L;
    } 
  }
  
  public Memoable copy() {
    return new DSTU7564Digest(this);
  }
  
  public void reset(Memoable paramMemoable) {
    DSTU7564Digest dSTU7564Digest = (DSTU7564Digest)paramMemoable;
    copyIn(dSTU7564Digest);
  }
}
