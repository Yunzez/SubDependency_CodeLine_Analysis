package org.bouncycastle.crypto.modes.gcm;

import org.bouncycastle.util.Pack;

public class Tables4kGCMMultiplier implements GCMMultiplier {
  private byte[] H;
  
  private long[][] T;
  
  public void init(byte[] paramArrayOfbyte) {
    if (this.T == null) {
      this.T = new long[256][2];
    } else if (0 != GCMUtil.areEqual(this.H, paramArrayOfbyte)) {
      return;
    } 
    this.H = new byte[16];
    GCMUtil.copy(paramArrayOfbyte, this.H);
    GCMUtil.asLongs(this.H, this.T[1]);
    GCMUtil.multiplyP7(this.T[1], this.T[1]);
    for (byte b = 2; b < 'Ā'; b += 2) {
      GCMUtil.divideP(this.T[b >> 1], this.T[b]);
      GCMUtil.xor(this.T[b], this.T[1], this.T[b + 1]);
    } 
  }
  
  public void multiplyH(byte[] paramArrayOfbyte) {
    long[] arrayOfLong = this.T[paramArrayOfbyte[15] & 0xFF];
    long l1 = arrayOfLong[0];
    long l2 = arrayOfLong[1];
    for (byte b = 14; b >= 0; b--) {
      arrayOfLong = this.T[paramArrayOfbyte[b] & 0xFF];
      long l = l2 << 56L;
      l2 = arrayOfLong[1] ^ (l2 >>> 8L | l1 << 56L);
      l1 = arrayOfLong[0] ^ l1 >>> 8L ^ l ^ l >>> 1L ^ l >>> 2L ^ l >>> 7L;
    } 
    Pack.longToBigEndian(l1, paramArrayOfbyte, 0);
    Pack.longToBigEndian(l2, paramArrayOfbyte, 8);
  }
}
