package org.bouncycastle.crypto.modes.gcm;

public class BasicGCMMultiplier implements GCMMultiplier {
  private long[] H;
  
  public void init(byte[] paramArrayOfbyte) {
    this.H = GCMUtil.asLongs(paramArrayOfbyte);
  }
  
  public void multiplyH(byte[] paramArrayOfbyte) {
    long[] arrayOfLong = GCMUtil.asLongs(paramArrayOfbyte);
    GCMUtil.multiply(arrayOfLong, this.H);
    GCMUtil.asBytes(arrayOfLong, paramArrayOfbyte);
  }
}
