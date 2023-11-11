package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Pack;

public class Tables64kGCMMultiplier implements GCMMultiplier {
  private byte[] H;
  
  private long[][][] T;
  
  public void init(byte[] paramArrayOfbyte) {
    if (this.T == null) {
      this.T = new long[16][256][2];
    } else if (0 != GCMUtil.areEqual(this.H, paramArrayOfbyte)) {
      return;
    } 
    this.H = new byte[16];
    GCMUtil.copy(paramArrayOfbyte, this.H);
    for (byte b = 0; b < 16; b++) {
      long[][] arrayOfLong = this.T[b];
      if (b == 0) {
        GCMUtil.asLongs(this.H, arrayOfLong[1]);
        GCMUtil.multiplyP7(arrayOfLong[1], arrayOfLong[1]);
      } else {
        GCMUtil.multiplyP8(this.T[b - 1][1], arrayOfLong[1]);
      } 
      for (byte b1 = 2; b1 < 'Ā'; b1 += 2) {
        GCMUtil.divideP(arrayOfLong[b1 >> 1], arrayOfLong[b1]);
        GCMUtil.xor(arrayOfLong[b1], arrayOfLong[1], arrayOfLong[b1 + 1]);
      } 
    } 
  }
  
  public void multiplyH(byte[] paramArrayOfbyte) {
    long[] arrayOfLong = this.T[15][paramArrayOfbyte[15] & 0xFF];
    long l1 = arrayOfLong[0];
    long l2 = arrayOfLong[1];
    for (byte b = 14; b >= 0; b--) {
      arrayOfLong = this.T[b][paramArrayOfbyte[b] & 0xFF];
      l1 ^= arrayOfLong[0];
      l2 ^= arrayOfLong[1];
    } 
    Pack.longToBigEndian(l1, paramArrayOfbyte, 0);
    Pack.longToBigEndian(l2, paramArrayOfbyte, 8);
  }
}
