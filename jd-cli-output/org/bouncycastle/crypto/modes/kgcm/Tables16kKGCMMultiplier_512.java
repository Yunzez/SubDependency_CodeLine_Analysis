package org.bouncycastle.crypto.modes.kgcm;

public class Tables16kKGCMMultiplier_512 implements KGCMMultiplier {
  private long[][] T;
  
  public void init(long[] paramArrayOflong) {
    if (this.T == null) {
      this.T = new long[256][8];
    } else if (KGCMUtil_512.equal(paramArrayOflong, this.T[1])) {
      return;
    } 
    KGCMUtil_512.copy(paramArrayOflong, this.T[1]);
    for (byte b = 2; b < 'Ā'; b += 2) {
      KGCMUtil_512.multiplyX(this.T[b >> 1], this.T[b]);
      KGCMUtil_512.add(this.T[b], this.T[1], this.T[b + 1]);
    } 
  }
  
  public void multiplyH(long[] paramArrayOflong) {
    long[] arrayOfLong = new long[8];
    KGCMUtil_512.copy(this.T[(int)(paramArrayOflong[7] >>> 56L) & 0xFF], arrayOfLong);
    for (byte b = 62; b >= 0; b--) {
      KGCMUtil_512.multiplyX8(arrayOfLong, arrayOfLong);
      KGCMUtil_512.add(this.T[(int)(paramArrayOflong[b >>> 3] >>> (b & 0x7) << 3) & 0xFF], arrayOfLong, arrayOfLong);
    } 
    KGCMUtil_512.copy(arrayOfLong, paramArrayOflong);
  }
}
