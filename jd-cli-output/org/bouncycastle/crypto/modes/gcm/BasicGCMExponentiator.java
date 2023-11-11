package org.bouncycastle.crypto.modes.gcm;

public class BasicGCMExponentiator implements GCMExponentiator {
  private long[] x;
  
  public void init(byte[] paramArrayOfbyte) {
    this.x = GCMUtil.asLongs(paramArrayOfbyte);
  }
  
  public void exponentiateX(long paramLong, byte[] paramArrayOfbyte) {
    long[] arrayOfLong = GCMUtil.oneAsLongs();
    if (paramLong > 0L) {
      long[] arrayOfLong1 = new long[2];
      GCMUtil.copy(this.x, arrayOfLong1);
      do {
        if ((paramLong & 0x1L) != 0L)
          GCMUtil.multiply(arrayOfLong, arrayOfLong1); 
        GCMUtil.square(arrayOfLong1, arrayOfLong1);
        paramLong >>>= 1L;
      } while (paramLong > 0L);
    } 
    GCMUtil.asBytes(arrayOfLong, paramArrayOfbyte);
  }
}
