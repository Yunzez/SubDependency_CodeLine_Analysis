package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

public class GOST3412_2015Engine implements BlockCipher {
  private static final byte[] PI = new byte[] { 
      -4, -18, -35, 17, -49, 110, 49, 22, -5, -60, 
      -6, -38, 35, -59, 4, 77, -23, 119, -16, -37, 
      -109, 46, -103, -70, 23, 54, -15, -69, 20, -51, 
      95, -63, -7, 24, 101, 90, -30, 92, -17, 33, 
      -127, 28, 60, 66, -117, 1, -114, 79, 5, -124, 
      2, -82, -29, 106, -113, -96, 6, 11, -19, -104, 
      Byte.MAX_VALUE, -44, -45, 31, -21, 52, 44, 81, -22, -56, 
      72, -85, -14, 42, 104, -94, -3, 58, -50, -52, 
      -75, 112, 14, 86, 8, 12, 118, 18, -65, 114, 
      19, 71, -100, -73, 93, -121, 21, -95, -106, 41, 
      16, 123, -102, -57, -13, -111, 120, 111, -99, -98, 
      -78, -79, 50, 117, 25, 61, -1, 53, -118, 126, 
      109, 84, -58, Byte.MIN_VALUE, -61, -67, 13, 87, -33, -11, 
      36, -87, 62, -88, 67, -55, -41, 121, -42, -10, 
      124, 34, -71, 3, -32, 15, -20, -34, 122, -108, 
      -80, -68, -36, -24, 40, 80, 78, 51, 10, 74, 
      -89, -105, 96, 115, 30, 0, 98, 68, 26, -72, 
      56, -126, 100, -97, 38, 65, -83, 69, 70, -110, 
      39, 94, 85, 47, -116, -93, -91, 125, 105, -43, 
      -107, 59, 7, 88, -77, 64, -122, -84, 29, -9, 
      48, 55, 107, -28, -120, -39, -25, -119, -31, 27, 
      -125, 73, 76, 63, -8, -2, -115, 83, -86, -112, 
      -54, -40, -123, 97, 32, 113, 103, -92, 45, 43, 
      9, 91, -53, -101, 37, -48, -66, -27, 108, 82, 
      89, -90, 116, -46, -26, -12, -76, -64, -47, 102, 
      -81, -62, 57, 75, 99, -74 };
  
  private static final byte[] inversePI = new byte[] { 
      -91, 45, 50, -113, 14, 48, 56, -64, 84, -26, 
      -98, 57, 85, 126, 82, -111, 100, 3, 87, 90, 
      28, 96, 7, 24, 33, 114, -88, -47, 41, -58, 
      -92, 63, -32, 39, -115, 12, -126, -22, -82, -76, 
      -102, 99, 73, -27, 66, -28, 21, -73, -56, 6, 
      112, -99, 65, 117, 25, -55, -86, -4, 77, -65, 
      42, 115, -124, -43, -61, -81, 43, -122, -89, -79, 
      -78, 91, 70, -45, -97, -3, -44, 15, -100, 47, 
      -101, 67, -17, -39, 121, -74, 83, Byte.MAX_VALUE, -63, -16, 
      35, -25, 37, 94, -75, 30, -94, -33, -90, -2, 
      -84, 34, -7, -30, 74, -68, 53, -54, -18, 120, 
      5, 107, 81, -31, 89, -93, -14, 113, 86, 17, 
      106, -119, -108, 101, -116, -69, 119, 60, 123, 40, 
      -85, -46, 49, -34, -60, 95, -52, -49, 118, 44, 
      -72, -40, 46, 54, -37, 105, -77, 20, -107, -66, 
      98, -95, 59, 22, 102, -23, 92, 108, 109, -83, 
      55, 97, 75, -71, -29, -70, -15, -96, -123, -125, 
      -38, 71, -59, -80, 51, -6, -106, 111, 110, -62, 
      -10, 80, -1, 93, -87, -114, 23, 27, -105, 125, 
      -20, 88, -9, 31, -5, 124, 9, 13, 122, 103, 
      69, -121, -36, -24, 79, 29, 78, 4, -21, -8, 
      -13, 62, 61, -67, -118, -120, -35, -51, 11, 19, 
      -104, 2, -109, Byte.MIN_VALUE, -112, -48, 36, 52, -53, -19, 
      -12, -50, -103, 16, 68, 64, -110, 58, 1, 38, 
      18, 26, 72, 104, -11, -127, -117, -57, -42, 32, 
      10, 8, 0, 76, -41, 116 };
  
  private final byte[] lFactors = new byte[] { 
      -108, 32, -123, 16, -62, -64, 1, -5, 1, -64, 
      -62, 16, -123, 32, -108, 1 };
  
  protected static final int BLOCK_SIZE = 16;
  
  private int KEY_LENGTH = 32;
  
  private int SUB_LENGTH = this.KEY_LENGTH / 2;
  
  private byte[][] subKeys = (byte[][])null;
  
  private boolean forEncryption;
  
  private byte[][] _gf_mul = init_gf256_mul_table();
  
  private static byte[][] init_gf256_mul_table() {
    byte[][] arrayOfByte = new byte[256][];
    for (byte b = 0; b < 'Ā'; b++) {
      arrayOfByte[b] = new byte[256];
      for (byte b1 = 0; b1 < 'Ā'; b1++)
        arrayOfByte[b][b1] = kuz_mul_gf256_slow((byte)b, (byte)b1); 
    } 
    return arrayOfByte;
  }
  
  private static byte kuz_mul_gf256_slow(byte paramByte1, byte paramByte2) {
    byte b1 = 0;
    for (byte b2 = 0; b2 < 8 && paramByte1 != 0 && paramByte2 != 0; b2 = (byte)(b2 + 1)) {
      if ((paramByte2 & 0x1) != 0)
        b1 = (byte)(b1 ^ paramByte1); 
      byte b = (byte)(paramByte1 & 0x80);
      paramByte1 = (byte)(paramByte1 << 1);
      if (b != 0)
        paramByte1 = (byte)(paramByte1 ^ 0xC3); 
      paramByte2 = (byte)(paramByte2 >> 1);
    } 
    return b1;
  }
  
  public String getAlgorithmName() {
    return "GOST3412_2015";
  }
  
  public int getBlockSize() {
    return 16;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) throws IllegalArgumentException {
    if (paramCipherParameters instanceof KeyParameter) {
      this.forEncryption = paramBoolean;
      generateSubKeys(((KeyParameter)paramCipherParameters).getKey());
    } else if (paramCipherParameters != null) {
      throw new IllegalArgumentException("invalid parameter passed to GOST3412_2015 init - " + paramCipherParameters.getClass().getName());
    } 
  }
  
  private void generateSubKeys(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length != this.KEY_LENGTH)
      throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!"); 
    this.subKeys = new byte[10][];
    for (byte b1 = 0; b1 < 10; b1++)
      this.subKeys[b1] = new byte[this.SUB_LENGTH]; 
    byte[] arrayOfByte1 = new byte[this.SUB_LENGTH];
    byte[] arrayOfByte2 = new byte[this.SUB_LENGTH];
    for (byte b2 = 0; b2 < this.SUB_LENGTH; b2++) {
      arrayOfByte1[b2] = paramArrayOfbyte[b2];
      this.subKeys[0][b2] = paramArrayOfbyte[b2];
      arrayOfByte2[b2] = paramArrayOfbyte[b2 + this.SUB_LENGTH];
      this.subKeys[1][b2] = paramArrayOfbyte[b2 + this.SUB_LENGTH];
    } 
    byte[] arrayOfByte3 = new byte[this.SUB_LENGTH];
    for (byte b3 = 1; b3 < 5; b3++) {
      for (byte b = 1; b <= 8; b++) {
        C(arrayOfByte3, 8 * (b3 - 1) + b);
        F(arrayOfByte3, arrayOfByte1, arrayOfByte2);
      } 
      System.arraycopy(arrayOfByte1, 0, this.subKeys[2 * b3], 0, this.SUB_LENGTH);
      System.arraycopy(arrayOfByte2, 0, this.subKeys[2 * b3 + 1], 0, this.SUB_LENGTH);
    } 
  }
  
  private void C(byte[] paramArrayOfbyte, int paramInt) {
    Arrays.clear(paramArrayOfbyte);
    paramArrayOfbyte[15] = (byte)paramInt;
    L(paramArrayOfbyte);
  }
  
  private void F(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    byte[] arrayOfByte = LSX(paramArrayOfbyte1, paramArrayOfbyte2);
    X(arrayOfByte, paramArrayOfbyte3);
    System.arraycopy(paramArrayOfbyte2, 0, paramArrayOfbyte3, 0, this.SUB_LENGTH);
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, 0, this.SUB_LENGTH);
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) throws DataLengthException, IllegalStateException {
    if (this.subKeys == null)
      throw new IllegalStateException("GOST3412_2015 engine not initialised"); 
    if (paramInt1 + 16 > paramArrayOfbyte1.length)
      throw new DataLengthException("input buffer too short"); 
    if (paramInt2 + 16 > paramArrayOfbyte2.length)
      throw new OutputLengthException("output buffer too short"); 
    GOST3412_2015Func(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2);
    return 16;
  }
  
  private void GOST3412_2015Func(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    byte[] arrayOfByte = new byte[16];
    System.arraycopy(paramArrayOfbyte1, paramInt1, arrayOfByte, 0, 16);
    if (this.forEncryption) {
      for (byte b = 0; b < 9; b++) {
        byte[] arrayOfByte1 = LSX(this.subKeys[b], arrayOfByte);
        arrayOfByte = Arrays.copyOf(arrayOfByte1, 16);
      } 
      X(arrayOfByte, this.subKeys[9]);
    } else {
      for (byte b = 9; b > 0; b--) {
        byte[] arrayOfByte1 = XSL(this.subKeys[b], arrayOfByte);
        arrayOfByte = Arrays.copyOf(arrayOfByte1, 16);
      } 
      X(arrayOfByte, this.subKeys[0]);
    } 
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, paramInt2, 16);
  }
  
  private byte[] LSX(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte = Arrays.copyOf(paramArrayOfbyte1, paramArrayOfbyte1.length);
    X(arrayOfByte, paramArrayOfbyte2);
    S(arrayOfByte);
    L(arrayOfByte);
    return arrayOfByte;
  }
  
  private byte[] XSL(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte = Arrays.copyOf(paramArrayOfbyte1, paramArrayOfbyte1.length);
    X(arrayOfByte, paramArrayOfbyte2);
    inverseL(arrayOfByte);
    inverseS(arrayOfByte);
    return arrayOfByte;
  }
  
  private void X(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    for (byte b = 0; b < paramArrayOfbyte1.length; b++)
      paramArrayOfbyte1[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]); 
  }
  
  private void S(byte[] paramArrayOfbyte) {
    for (byte b = 0; b < paramArrayOfbyte.length; b++)
      paramArrayOfbyte[b] = PI[unsignedByte(paramArrayOfbyte[b])]; 
  }
  
  private void inverseS(byte[] paramArrayOfbyte) {
    for (byte b = 0; b < paramArrayOfbyte.length; b++)
      paramArrayOfbyte[b] = inversePI[unsignedByte(paramArrayOfbyte[b])]; 
  }
  
  private int unsignedByte(byte paramByte) {
    return paramByte & 0xFF;
  }
  
  private void L(byte[] paramArrayOfbyte) {
    for (byte b = 0; b < 16; b++)
      R(paramArrayOfbyte); 
  }
  
  private void inverseL(byte[] paramArrayOfbyte) {
    for (byte b = 0; b < 16; b++)
      inverseR(paramArrayOfbyte); 
  }
  
  private void R(byte[] paramArrayOfbyte) {
    byte b = l(paramArrayOfbyte);
    System.arraycopy(paramArrayOfbyte, 0, paramArrayOfbyte, 1, 15);
    paramArrayOfbyte[0] = b;
  }
  
  private void inverseR(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[16];
    System.arraycopy(paramArrayOfbyte, 1, arrayOfByte, 0, 15);
    arrayOfByte[15] = paramArrayOfbyte[0];
    byte b = l(arrayOfByte);
    System.arraycopy(paramArrayOfbyte, 1, paramArrayOfbyte, 0, 15);
    paramArrayOfbyte[15] = b;
  }
  
  private byte l(byte[] paramArrayOfbyte) {
    byte b = paramArrayOfbyte[15];
    for (byte b1 = 14; b1 >= 0; b1--)
      b = (byte)(b ^ this._gf_mul[unsignedByte(paramArrayOfbyte[b1])][unsignedByte(this.lFactors[b1])]); 
    return b;
  }
  
  public void reset() {}
}
