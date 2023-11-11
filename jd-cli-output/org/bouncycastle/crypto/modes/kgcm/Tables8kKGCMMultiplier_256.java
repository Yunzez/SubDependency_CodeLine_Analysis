package org.bouncycastle.crypto.modes.kgcm;

public class Tables8kKGCMMultiplier_256 implements KGCMMultiplier {
  private long[][] T;
  
  public void init(long[] paramArrayOflong) {
    if (this.T == null) {
      this.T = new long[256][4];
    } else if (KGCMUtil_256.equal(paramArrayOflong, this.T[1])) {
      return;
    } 
    KGCMUtil_256.copy(paramArrayOflong, this.T[1]);
    for (byte b = 2; b < 'Ā'; b += 2) {
      KGCMUtil_256.multiplyX(this.T[b >> 1], this.T[b]);
      KGCMUtil_256.add(this.T[b], this.T[1], this.T[b + 1]);
    } 
  }
  
  public void multiplyH(long[] paramArrayOflong) {
    long[] arrayOfLong = new long[4];
    KGCMUtil_256.copy(this.T[(int)(paramArrayOflong[3] >>> 56L) & 0xFF], arrayOfLong);
    for (byte b = 30; b >= 0; b--) {
      KGCMUtil_256.multiplyX8(arrayOfLong, arrayOfLong);
      KGCMUtil_256.add(this.T[(int)(paramArrayOflong[b >>> 3] >>> (b & 0x7) << 3) & 0xFF], arrayOfLong, arrayOfLong);
    } 
    KGCMUtil_256.copy(arrayOfLong, paramArrayOflong);
  }
}
