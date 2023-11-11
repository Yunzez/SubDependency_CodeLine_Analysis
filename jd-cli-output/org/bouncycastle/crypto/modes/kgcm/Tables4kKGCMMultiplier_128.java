package org.bouncycastle.crypto.modes.kgcm;

public class Tables4kKGCMMultiplier_128 implements KGCMMultiplier {
  private long[][] T;
  
  public void init(long[] paramArrayOflong) {
    if (this.T == null) {
      this.T = new long[256][2];
    } else if (KGCMUtil_128.equal(paramArrayOflong, this.T[1])) {
      return;
    } 
    KGCMUtil_128.copy(paramArrayOflong, this.T[1]);
    for (byte b = 2; b < 'Ā'; b += 2) {
      KGCMUtil_128.multiplyX(this.T[b >> 1], this.T[b]);
      KGCMUtil_128.add(this.T[b], this.T[1], this.T[b + 1]);
    } 
  }
  
  public void multiplyH(long[] paramArrayOflong) {
    long[] arrayOfLong = new long[2];
    KGCMUtil_128.copy(this.T[(int)(paramArrayOflong[1] >>> 56L) & 0xFF], arrayOfLong);
    for (byte b = 14; b >= 0; b--) {
      KGCMUtil_128.multiplyX8(arrayOfLong, arrayOfLong);
      KGCMUtil_128.add(this.T[(int)(paramArrayOflong[b >>> 3] >>> (b & 0x7) << 3) & 0xFF], arrayOfLong, arrayOfLong);
    } 
    KGCMUtil_128.copy(arrayOfLong, paramArrayOflong);
  }
}
