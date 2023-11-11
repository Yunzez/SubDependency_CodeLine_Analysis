package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Pack;

public class Tables8kGCMMultiplier implements GCMMultiplier {
  private byte[] H;
  
  private long[][][] T;
  
  public void init(byte[] paramArrayOfbyte) {
    if (this.T == null) {
      this.T = new long[32][16][2];
    } else if (0 != GCMUtil.areEqual(this.H, paramArrayOfbyte)) {
      return;
    } 
    this.H = new byte[16];
    GCMUtil.copy(paramArrayOfbyte, this.H);
    for (byte b = 0; b < 32; b++) {
      long[][] arrayOfLong = this.T[b];
      if (b == 0) {
        GCMUtil.asLongs(this.H, arrayOfLong[1]);
        GCMUtil.multiplyP3(arrayOfLong[1], arrayOfLong[1]);
      } else {
        GCMUtil.multiplyP4(this.T[b - 1][1], arrayOfLong[1]);
      } 
      for (byte b1 = 2; b1 < 16; b1 += 2) {
        GCMUtil.divideP(arrayOfLong[b1 >> 1], arrayOfLong[b1]);
        GCMUtil.xor(arrayOfLong[b1], arrayOfLong[1], arrayOfLong[b1 + 1]);
      } 
    } 
  }
  
  public void multiplyH(byte[] paramArrayOfbyte) {
    long l1 = 0L;
    long l2 = 0L;
    for (byte b = 15; b >= 0; b--) {
      long[] arrayOfLong1 = this.T[b + b + 1][paramArrayOfbyte[b] & 0xF];
      long[] arrayOfLong2 = this.T[b + b][(paramArrayOfbyte[b] & 0xF0) >>> 4];
      l1 ^= arrayOfLong1[0] ^ arrayOfLong2[0];
      l2 ^= arrayOfLong1[1] ^ arrayOfLong2[1];
    } 
    Pack.longToBigEndian(l1, paramArrayOfbyte, 0);
    Pack.longToBigEndian(l2, paramArrayOfbyte, 8);
  }
}
