package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Memoable;

public class Zuc128CoreEngine implements StreamCipher, Memoable {
  private static final byte[] S0 = new byte[] { 
      62, 114, 91, 71, -54, -32, 0, 51, 4, -47, 
      84, -104, 9, -71, 109, -53, 123, 27, -7, 50, 
      -81, -99, 106, -91, -72, 45, -4, 29, 8, 83, 
      3, -112, 77, 78, -124, -103, -28, -50, -39, -111, 
      -35, -74, -123, 72, -117, 41, 110, -84, -51, -63, 
      -8, 30, 115, 67, 105, -58, -75, -67, -3, 57, 
      99, 32, -44, 56, 118, 125, -78, -89, -49, -19, 
      87, -59, -13, 44, -69, 20, 33, 6, 85, -101, 
      -29, -17, 94, 49, 79, Byte.MAX_VALUE, 90, -92, 13, -126, 
      81, 73, 95, -70, 88, 28, 74, 22, -43, 23, 
      -88, -110, 36, 31, -116, -1, -40, -82, 46, 1, 
      -45, -83, 59, 75, -38, 70, -21, -55, -34, -102, 
      -113, -121, -41, 58, Byte.MIN_VALUE, 111, 47, -56, -79, -76, 
      55, -9, 10, 34, 19, 40, 124, -52, 60, -119, 
      -57, -61, -106, 86, 7, -65, 126, -16, 11, 43, 
      -105, 82, 53, 65, 121, 97, -90, 76, 16, -2, 
      -68, 38, -107, -120, -118, -80, -93, -5, -64, 24, 
      -108, -14, -31, -27, -23, 93, -48, -36, 17, 102, 
      100, 92, -20, 89, 66, 117, 18, -11, 116, -100, 
      -86, 35, 14, -122, -85, -66, 42, 2, -25, 103, 
      -26, 68, -94, 108, -62, -109, -97, -15, -10, -6, 
      54, -46, 80, 104, -98, 98, 113, 21, 61, -42, 
      64, -60, -30, 15, -114, -125, 119, 107, 37, 5, 
      63, 12, 48, -22, 112, -73, -95, -24, -87, 101, 
      -115, 39, 26, -37, -127, -77, -96, -12, 69, 122, 
      25, -33, -18, 120, 52, 96 };
  
  private static final byte[] S1 = new byte[] { 
      85, -62, 99, 113, 59, -56, 71, -122, -97, 60, 
      -38, 91, 41, -86, -3, 119, -116, -59, -108, 12, 
      -90, 26, 19, 0, -29, -88, 22, 114, 64, -7, 
      -8, 66, 68, 38, 104, -106, -127, -39, 69, 62, 
      16, 118, -58, -89, -117, 57, 67, -31, 58, -75, 
      86, 42, -64, 109, -77, 5, 34, 102, -65, -36, 
      11, -6, 98, 72, -35, 32, 17, 6, 54, -55, 
      -63, -49, -10, 39, 82, -69, 105, -11, -44, -121, 
      Byte.MAX_VALUE, -124, 76, -46, -100, 87, -92, -68, 79, -102, 
      -33, -2, -42, -115, 122, -21, 43, 83, -40, 92, 
      -95, 20, 23, -5, 35, -43, 125, 48, 103, 115, 
      8, 9, -18, -73, 112, 63, 97, -78, 25, -114, 
      78, -27, 75, -109, -113, 93, -37, -87, -83, -15, 
      -82, 46, -53, 13, -4, -12, 45, 70, 110, 29, 
      -105, -24, -47, -23, 77, 55, -91, 117, 94, -125, 
      -98, -85, -126, -99, -71, 28, -32, -51, 73, -119, 
      1, -74, -67, 88, 36, -94, 95, 56, 120, -103, 
      21, -112, 80, -72, -107, -28, -48, -111, -57, -50, 
      -19, 15, -76, 111, -96, -52, -16, 2, 74, 121, 
      -61, -34, -93, -17, -22, 81, -26, 107, 24, -20, 
      27, 44, Byte.MIN_VALUE, -9, 116, -25, -1, 33, 90, 106, 
      84, 30, 65, 49, -110, 53, -60, 51, 7, 10, 
      -70, 126, 14, 52, -120, -79, -104, 124, -13, 61, 
      96, 108, 123, -54, -45, 31, 50, 101, 4, 40, 
      100, -66, -123, -101, 47, 89, -118, -41, -80, 37, 
      -84, -81, 18, 3, -30, -14 };
  
  private static final short[] EK_d = new short[] { 
      17623, 9916, 25195, 4958, 22409, 13794, 28981, 2479, 19832, 12051, 
      27588, 6897, 24102, 15437, 30874, 18348 };
  
  private final int[] LFSR = new int[16];
  
  private final int[] F = new int[2];
  
  private final int[] BRC = new int[4];
  
  private int theIndex;
  
  private final byte[] keyStream = new byte[4];
  
  private int theIterations;
  
  private Zuc128CoreEngine theResetState;
  
  protected Zuc128CoreEngine() {}
  
  protected Zuc128CoreEngine(Zuc128CoreEngine paramZuc128CoreEngine) {
    reset(paramZuc128CoreEngine);
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    CipherParameters cipherParameters = paramCipherParameters;
    byte[] arrayOfByte1 = null;
    byte[] arrayOfByte2 = null;
    if (cipherParameters instanceof ParametersWithIV) {
      ParametersWithIV parametersWithIV = (ParametersWithIV)cipherParameters;
      arrayOfByte2 = parametersWithIV.getIV();
      cipherParameters = parametersWithIV.getParameters();
    } 
    if (cipherParameters instanceof KeyParameter) {
      KeyParameter keyParameter = (KeyParameter)cipherParameters;
      arrayOfByte1 = keyParameter.getKey();
    } 
    this.theIndex = 0;
    this.theIterations = 0;
    setKeyAndIV(arrayOfByte1, arrayOfByte2);
    this.theResetState = (Zuc128CoreEngine)copy();
  }
  
  protected int getMaxIterations() {
    return 2047;
  }
  
  public String getAlgorithmName() {
    return "Zuc-128";
  }
  
  public int processBytes(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    if (this.theResetState == null)
      throw new IllegalStateException(getAlgorithmName() + " not initialised"); 
    if (paramInt1 + paramInt2 > paramArrayOfbyte1.length)
      throw new DataLengthException("input buffer too short"); 
    if (paramInt3 + paramInt2 > paramArrayOfbyte2.length)
      throw new OutputLengthException("output buffer too short"); 
    for (byte b = 0; b < paramInt2; b++)
      paramArrayOfbyte2[b + paramInt3] = returnByte(paramArrayOfbyte1[b + paramInt1]); 
    return paramInt2;
  }
  
  public void reset() {
    if (this.theResetState != null)
      reset(this.theResetState); 
  }
  
  public byte returnByte(byte paramByte) {
    if (this.theIndex == 0)
      makeKeyStream(); 
    byte b = (byte)(this.keyStream[this.theIndex] ^ paramByte);
    this.theIndex = (this.theIndex + 1) % 4;
    return b;
  }
  
  public static void encode32be(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    paramArrayOfbyte[paramInt2] = (byte)(paramInt1 >> 24);
    paramArrayOfbyte[paramInt2 + 1] = (byte)(paramInt1 >> 16);
    paramArrayOfbyte[paramInt2 + 2] = (byte)(paramInt1 >> 8);
    paramArrayOfbyte[paramInt2 + 3] = (byte)paramInt1;
  }
  
  private int AddM(int paramInt1, int paramInt2) {
    int i = paramInt1 + paramInt2;
    return (i & Integer.MAX_VALUE) + (i >>> 31);
  }
  
  private static int MulByPow2(int paramInt1, int paramInt2) {
    return (paramInt1 << paramInt2 | paramInt1 >>> 31 - paramInt2) & Integer.MAX_VALUE;
  }
  
  private void LFSRWithInitialisationMode(int paramInt) {
    int i = this.LFSR[0];
    int j = MulByPow2(this.LFSR[0], 8);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[4], 20);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[10], 21);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[13], 17);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[15], 15);
    i = AddM(i, j);
    i = AddM(i, paramInt);
    this.LFSR[0] = this.LFSR[1];
    this.LFSR[1] = this.LFSR[2];
    this.LFSR[2] = this.LFSR[3];
    this.LFSR[3] = this.LFSR[4];
    this.LFSR[4] = this.LFSR[5];
    this.LFSR[5] = this.LFSR[6];
    this.LFSR[6] = this.LFSR[7];
    this.LFSR[7] = this.LFSR[8];
    this.LFSR[8] = this.LFSR[9];
    this.LFSR[9] = this.LFSR[10];
    this.LFSR[10] = this.LFSR[11];
    this.LFSR[11] = this.LFSR[12];
    this.LFSR[12] = this.LFSR[13];
    this.LFSR[13] = this.LFSR[14];
    this.LFSR[14] = this.LFSR[15];
    this.LFSR[15] = i;
  }
  
  private void LFSRWithWorkMode() {
    int i = this.LFSR[0];
    int j = MulByPow2(this.LFSR[0], 8);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[4], 20);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[10], 21);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[13], 17);
    i = AddM(i, j);
    j = MulByPow2(this.LFSR[15], 15);
    i = AddM(i, j);
    this.LFSR[0] = this.LFSR[1];
    this.LFSR[1] = this.LFSR[2];
    this.LFSR[2] = this.LFSR[3];
    this.LFSR[3] = this.LFSR[4];
    this.LFSR[4] = this.LFSR[5];
    this.LFSR[5] = this.LFSR[6];
    this.LFSR[6] = this.LFSR[7];
    this.LFSR[7] = this.LFSR[8];
    this.LFSR[8] = this.LFSR[9];
    this.LFSR[9] = this.LFSR[10];
    this.LFSR[10] = this.LFSR[11];
    this.LFSR[11] = this.LFSR[12];
    this.LFSR[12] = this.LFSR[13];
    this.LFSR[13] = this.LFSR[14];
    this.LFSR[14] = this.LFSR[15];
    this.LFSR[15] = i;
  }
  
  private void BitReorganization() {
    this.BRC[0] = (this.LFSR[15] & 0x7FFF8000) << 1 | this.LFSR[14] & 0xFFFF;
    this.BRC[1] = (this.LFSR[11] & 0xFFFF) << 16 | this.LFSR[9] >>> 15;
    this.BRC[2] = (this.LFSR[7] & 0xFFFF) << 16 | this.LFSR[5] >>> 15;
    this.BRC[3] = (this.LFSR[2] & 0xFFFF) << 16 | this.LFSR[0] >>> 15;
  }
  
  static int ROT(int paramInt1, int paramInt2) {
    return paramInt1 << paramInt2 | paramInt1 >>> 32 - paramInt2;
  }
  
  private static int L1(int paramInt) {
    return paramInt ^ ROT(paramInt, 2) ^ ROT(paramInt, 10) ^ ROT(paramInt, 18) ^ ROT(paramInt, 24);
  }
  
  private static int L2(int paramInt) {
    return paramInt ^ ROT(paramInt, 8) ^ ROT(paramInt, 14) ^ ROT(paramInt, 22) ^ ROT(paramInt, 30);
  }
  
  private static int MAKEU32(byte paramByte1, byte paramByte2, byte paramByte3, byte paramByte4) {
    return (paramByte1 & 0xFF) << 24 | (paramByte2 & 0xFF) << 16 | (paramByte3 & 0xFF) << 8 | paramByte4 & 0xFF;
  }
  
  int F() {
    int i = (this.BRC[0] ^ this.F[0]) + this.F[1];
    int j = this.F[0] + this.BRC[1];
    int k = this.F[1] ^ this.BRC[2];
    int m = L1(j << 16 | k >>> 16);
    int n = L2(k << 16 | j >>> 16);
    this.F[0] = MAKEU32(S0[m >>> 24], S1[m >>> 16 & 0xFF], S0[m >>> 8 & 0xFF], S1[m & 0xFF]);
    this.F[1] = MAKEU32(S0[n >>> 24], S1[n >>> 16 & 0xFF], S0[n >>> 8 & 0xFF], S1[n & 0xFF]);
    return i;
  }
  
  private static int MAKEU31(byte paramByte1, short paramShort, byte paramByte2) {
    return (paramByte1 & 0xFF) << 23 | (paramShort & 0xFFFF) << 8 | paramByte2 & 0xFF;
  }
  
  protected void setKeyAndIV(int[] paramArrayOfint, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (paramArrayOfbyte1 == null || paramArrayOfbyte1.length != 16)
      throw new IllegalArgumentException("A key of 16 bytes is needed"); 
    if (paramArrayOfbyte2 == null || paramArrayOfbyte2.length != 16)
      throw new IllegalArgumentException("An IV of 16 bytes is needed"); 
    this.LFSR[0] = MAKEU31(paramArrayOfbyte1[0], EK_d[0], paramArrayOfbyte2[0]);
    this.LFSR[1] = MAKEU31(paramArrayOfbyte1[1], EK_d[1], paramArrayOfbyte2[1]);
    this.LFSR[2] = MAKEU31(paramArrayOfbyte1[2], EK_d[2], paramArrayOfbyte2[2]);
    this.LFSR[3] = MAKEU31(paramArrayOfbyte1[3], EK_d[3], paramArrayOfbyte2[3]);
    this.LFSR[4] = MAKEU31(paramArrayOfbyte1[4], EK_d[4], paramArrayOfbyte2[4]);
    this.LFSR[5] = MAKEU31(paramArrayOfbyte1[5], EK_d[5], paramArrayOfbyte2[5]);
    this.LFSR[6] = MAKEU31(paramArrayOfbyte1[6], EK_d[6], paramArrayOfbyte2[6]);
    this.LFSR[7] = MAKEU31(paramArrayOfbyte1[7], EK_d[7], paramArrayOfbyte2[7]);
    this.LFSR[8] = MAKEU31(paramArrayOfbyte1[8], EK_d[8], paramArrayOfbyte2[8]);
    this.LFSR[9] = MAKEU31(paramArrayOfbyte1[9], EK_d[9], paramArrayOfbyte2[9]);
    this.LFSR[10] = MAKEU31(paramArrayOfbyte1[10], EK_d[10], paramArrayOfbyte2[10]);
    this.LFSR[11] = MAKEU31(paramArrayOfbyte1[11], EK_d[11], paramArrayOfbyte2[11]);
    this.LFSR[12] = MAKEU31(paramArrayOfbyte1[12], EK_d[12], paramArrayOfbyte2[12]);
    this.LFSR[13] = MAKEU31(paramArrayOfbyte1[13], EK_d[13], paramArrayOfbyte2[13]);
    this.LFSR[14] = MAKEU31(paramArrayOfbyte1[14], EK_d[14], paramArrayOfbyte2[14]);
    this.LFSR[15] = MAKEU31(paramArrayOfbyte1[15], EK_d[15], paramArrayOfbyte2[15]);
  }
  
  private void setKeyAndIV(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    setKeyAndIV(this.LFSR, paramArrayOfbyte1, paramArrayOfbyte2);
    this.F[0] = 0;
    this.F[1] = 0;
    for (byte b = 32; b > 0; b--) {
      BitReorganization();
      int i = F();
      LFSRWithInitialisationMode(i >>> 1);
    } 
    BitReorganization();
    F();
    LFSRWithWorkMode();
  }
  
  private void makeKeyStream() {
    encode32be(makeKeyStreamWord(), this.keyStream, 0);
  }
  
  protected int makeKeyStreamWord() {
    if (this.theIterations++ >= getMaxIterations())
      throw new IllegalStateException("Too much data processed by singleKey/IV"); 
    BitReorganization();
    int i = F() ^ this.BRC[3];
    LFSRWithWorkMode();
    return i;
  }
  
  public Memoable copy() {
    return new Zuc128CoreEngine(this);
  }
  
  public void reset(Memoable paramMemoable) {
    Zuc128CoreEngine zuc128CoreEngine = (Zuc128CoreEngine)paramMemoable;
    System.arraycopy(zuc128CoreEngine.LFSR, 0, this.LFSR, 0, this.LFSR.length);
    System.arraycopy(zuc128CoreEngine.F, 0, this.F, 0, this.F.length);
    System.arraycopy(zuc128CoreEngine.BRC, 0, this.BRC, 0, this.BRC.length);
    System.arraycopy(zuc128CoreEngine.keyStream, 0, this.keyStream, 0, this.keyStream.length);
    this.theIndex = zuc128CoreEngine.theIndex;
    this.theIterations = zuc128CoreEngine.theIterations;
    this.theResetState = zuc128CoreEngine;
  }
}
