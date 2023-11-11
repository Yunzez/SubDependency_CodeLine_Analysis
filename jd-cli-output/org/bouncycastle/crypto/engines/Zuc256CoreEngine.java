package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Memoable;

public class Zuc256CoreEngine extends Zuc128CoreEngine {
  private static final byte[] EK_d = new byte[] { 
      34, 47, 36, 42, 109, 64, 64, 64, 64, 64, 
      64, 64, 64, 82, 16, 48 };
  
  private static final byte[] EK_d32 = new byte[] { 
      34, 47, 37, 42, 109, 64, 64, 64, 64, 64, 
      64, 64, 64, 82, 16, 48 };
  
  private static final byte[] EK_d64 = new byte[] { 
      35, 47, 36, 42, 109, 64, 64, 64, 64, 64, 
      64, 64, 64, 82, 16, 48 };
  
  private static final byte[] EK_d128 = new byte[] { 
      35, 47, 37, 42, 109, 64, 64, 64, 64, 64, 
      64, 64, 64, 82, 16, 48 };
  
  private byte[] theD;
  
  protected Zuc256CoreEngine() {
    this.theD = EK_d;
  }
  
  protected Zuc256CoreEngine(int paramInt) {
    switch (paramInt) {
      case 32:
        this.theD = EK_d32;
        return;
      case 64:
        this.theD = EK_d64;
        return;
      case 128:
        this.theD = EK_d128;
        return;
    } 
    throw new IllegalArgumentException("Unsupported length: " + paramInt);
  }
  
  protected Zuc256CoreEngine(Zuc256CoreEngine paramZuc256CoreEngine) {
    super(paramZuc256CoreEngine);
  }
  
  protected int getMaxIterations() {
    return 625;
  }
  
  public String getAlgorithmName() {
    return "Zuc-256";
  }
  
  private static int MAKEU31(byte paramByte1, byte paramByte2, byte paramByte3, byte paramByte4) {
    return (paramByte1 & 0xFF) << 23 | (paramByte2 & 0xFF) << 16 | (paramByte3 & 0xFF) << 8 | paramByte4 & 0xFF;
  }
  
  protected void setKeyAndIV(int[] paramArrayOfint, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (paramArrayOfbyte1 == null || paramArrayOfbyte1.length != 32)
      throw new IllegalArgumentException("A key of 32 bytes is needed"); 
    if (paramArrayOfbyte2 == null || paramArrayOfbyte2.length != 25)
      throw new IllegalArgumentException("An IV of 25 bytes is needed"); 
    paramArrayOfint[0] = MAKEU31(paramArrayOfbyte1[0], this.theD[0], paramArrayOfbyte1[21], paramArrayOfbyte1[16]);
    paramArrayOfint[1] = MAKEU31(paramArrayOfbyte1[1], this.theD[1], paramArrayOfbyte1[22], paramArrayOfbyte1[17]);
    paramArrayOfint[2] = MAKEU31(paramArrayOfbyte1[2], this.theD[2], paramArrayOfbyte1[23], paramArrayOfbyte1[18]);
    paramArrayOfint[3] = MAKEU31(paramArrayOfbyte1[3], this.theD[3], paramArrayOfbyte1[24], paramArrayOfbyte1[19]);
    paramArrayOfint[4] = MAKEU31(paramArrayOfbyte1[4], this.theD[4], paramArrayOfbyte1[25], paramArrayOfbyte1[20]);
    paramArrayOfint[5] = MAKEU31(paramArrayOfbyte2[0], (byte)(this.theD[5] | paramArrayOfbyte2[17] & 0x3F), paramArrayOfbyte1[5], paramArrayOfbyte1[26]);
    paramArrayOfint[6] = MAKEU31(paramArrayOfbyte2[1], (byte)(this.theD[6] | paramArrayOfbyte2[18] & 0x3F), paramArrayOfbyte1[6], paramArrayOfbyte1[27]);
    paramArrayOfint[7] = MAKEU31(paramArrayOfbyte2[10], (byte)(this.theD[7] | paramArrayOfbyte2[19] & 0x3F), paramArrayOfbyte1[7], paramArrayOfbyte2[2]);
    paramArrayOfint[8] = MAKEU31(paramArrayOfbyte1[8], (byte)(this.theD[8] | paramArrayOfbyte2[20] & 0x3F), paramArrayOfbyte2[3], paramArrayOfbyte2[11]);
    paramArrayOfint[9] = MAKEU31(paramArrayOfbyte1[9], (byte)(this.theD[9] | paramArrayOfbyte2[21] & 0x3F), paramArrayOfbyte2[12], paramArrayOfbyte2[4]);
    paramArrayOfint[10] = MAKEU31(paramArrayOfbyte2[5], (byte)(this.theD[10] | paramArrayOfbyte2[22] & 0x3F), paramArrayOfbyte1[10], paramArrayOfbyte1[28]);
    paramArrayOfint[11] = MAKEU31(paramArrayOfbyte1[11], (byte)(this.theD[11] | paramArrayOfbyte2[23] & 0x3F), paramArrayOfbyte2[6], paramArrayOfbyte2[13]);
    paramArrayOfint[12] = MAKEU31(paramArrayOfbyte1[12], (byte)(this.theD[12] | paramArrayOfbyte2[24] & 0x3F), paramArrayOfbyte2[7], paramArrayOfbyte2[14]);
    paramArrayOfint[13] = MAKEU31(paramArrayOfbyte1[13], this.theD[13], paramArrayOfbyte2[15], paramArrayOfbyte2[8]);
    paramArrayOfint[14] = MAKEU31(paramArrayOfbyte1[14], (byte)(this.theD[14] | paramArrayOfbyte1[31] >>> 4 & 0xF), paramArrayOfbyte2[16], paramArrayOfbyte2[9]);
    paramArrayOfint[15] = MAKEU31(paramArrayOfbyte1[15], (byte)(this.theD[15] | paramArrayOfbyte1[31] & 0xF), paramArrayOfbyte1[30], paramArrayOfbyte1[29]);
  }
  
  public Memoable copy() {
    return new Zuc256CoreEngine(this);
  }
  
  public void reset(Memoable paramMemoable) {
    Zuc256CoreEngine zuc256CoreEngine = (Zuc256CoreEngine)paramMemoable;
    super.reset(paramMemoable);
    this.theD = zuc256CoreEngine.theD;
  }
}
