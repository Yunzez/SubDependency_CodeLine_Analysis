package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class WotsPlus {
  private final SPHINCSPlusEngine engine;
  
  private final int w;
  
  WotsPlus(SPHINCSPlusEngine paramSPHINCSPlusEngine) {
    this.engine = paramSPHINCSPlusEngine;
    this.w = this.engine.WOTS_W;
  }
  
  byte[] pkGen(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, ADRS paramADRS) {
    ADRS aDRS = new ADRS(paramADRS);
    byte[][] arrayOfByte = new byte[this.engine.WOTS_LEN][];
    for (byte b = 0; b < this.engine.WOTS_LEN; b++) {
      ADRS aDRS1 = new ADRS(paramADRS);
      aDRS1.setChainAddress(b);
      aDRS1.setHashAddress(0);
      byte[] arrayOfByte1 = this.engine.PRF(paramArrayOfbyte1, aDRS1);
      arrayOfByte[b] = chain(arrayOfByte1, 0, this.w - 1, paramArrayOfbyte2, aDRS1);
    } 
    aDRS.setType(1);
    aDRS.setKeyPairAddress(paramADRS.getKeyPairAddress());
    return this.engine.T_l(paramArrayOfbyte2, aDRS, Arrays.concatenate(arrayOfByte));
  }
  
  byte[] chain(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, ADRS paramADRS) {
    if (paramInt2 == 0)
      return Arrays.clone(paramArrayOfbyte1); 
    if (paramInt1 + paramInt2 > this.w - 1)
      return null; 
    null = chain(paramArrayOfbyte1, paramInt1, paramInt2 - 1, paramArrayOfbyte2, paramADRS);
    paramADRS.setHashAddress(paramInt1 + paramInt2 - 1);
    return this.engine.F(paramArrayOfbyte2, paramADRS, null);
  }
  
  public byte[] sign(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, ADRS paramADRS) {
    ADRS aDRS = new ADRS(paramADRS);
    int i = 0;
    int[] arrayOfInt = base_w(paramArrayOfbyte1, this.w, this.engine.WOTS_LEN1);
    int j;
    for (j = 0; j < this.engine.WOTS_LEN1; j++)
      i += this.w - 1 - arrayOfInt[j]; 
    if (this.engine.WOTS_LOGW % 8 != 0)
      i <<= 8 - this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW % 8; 
    j = (this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW + 7) / 8;
    byte[] arrayOfByte = Pack.intToBigEndian(i);
    arrayOfInt = Arrays.concatenate(arrayOfInt, base_w(Arrays.copyOfRange(arrayOfByte, j, arrayOfByte.length), this.w, this.engine.WOTS_LEN2));
    byte[][] arrayOfByte1 = new byte[this.engine.WOTS_LEN][];
    for (byte b = 0; b < this.engine.WOTS_LEN; b++) {
      aDRS.setChainAddress(b);
      aDRS.setHashAddress(0);
      byte[] arrayOfByte2 = this.engine.PRF(paramArrayOfbyte2, aDRS);
      arrayOfByte1[b] = chain(arrayOfByte2, 0, arrayOfInt[b], paramArrayOfbyte3, aDRS);
    } 
    return Arrays.concatenate(arrayOfByte1);
  }
  
  int[] base_w(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte b1 = 0;
    byte b2 = 0;
    byte b = 0;
    int i = 0;
    int[] arrayOfInt = new int[paramInt2];
    for (byte b3 = 0; b3 < paramInt2; b3++) {
      if (!i) {
        b = paramArrayOfbyte[b1];
        b1++;
        i += true;
      } 
      i -= this.engine.WOTS_LOGW;
      arrayOfInt[b2] = b >>> i & paramInt1 - 1;
      b2++;
    } 
    return arrayOfInt;
  }
  
  public byte[] pkFromSig(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, ADRS paramADRS) {
    int i = 0;
    ADRS aDRS = new ADRS(paramADRS);
    int[] arrayOfInt = base_w(paramArrayOfbyte2, this.w, this.engine.WOTS_LEN1);
    int j;
    for (j = 0; j < this.engine.WOTS_LEN1; j++)
      i += this.w - 1 - arrayOfInt[j]; 
    i <<= 8 - this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW % 8;
    j = (this.engine.WOTS_LEN2 * this.engine.WOTS_LOGW + 7) / 8;
    arrayOfInt = Arrays.concatenate(arrayOfInt, base_w(Arrays.copyOfRange(Pack.intToBigEndian(i), 4 - j, 4), this.w, this.engine.WOTS_LEN2));
    byte[] arrayOfByte = new byte[this.engine.N];
    byte[][] arrayOfByte1 = new byte[this.engine.WOTS_LEN][];
    for (byte b = 0; b < this.engine.WOTS_LEN; b++) {
      paramADRS.setChainAddress(b);
      System.arraycopy(paramArrayOfbyte1, b * this.engine.N, arrayOfByte, 0, this.engine.N);
      arrayOfByte1[b] = chain(arrayOfByte, arrayOfInt[b], this.w - 1 - arrayOfInt[b], paramArrayOfbyte3, paramADRS);
    } 
    aDRS.setType(1);
    aDRS.setKeyPairAddress(paramADRS.getKeyPairAddress());
    return this.engine.T_l(paramArrayOfbyte3, aDRS, Arrays.concatenate(arrayOfByte1));
  }
}
