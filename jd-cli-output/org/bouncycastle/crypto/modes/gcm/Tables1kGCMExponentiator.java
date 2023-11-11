package org.bouncycastle.crypto.modes.gcm;

import java.util.Vector;

public class Tables1kGCMExponentiator implements GCMExponentiator {
  private Vector lookupPowX2;
  
  public void init(byte[] paramArrayOfbyte) {
    long[] arrayOfLong = GCMUtil.asLongs(paramArrayOfbyte);
    if (this.lookupPowX2 != null && 0L != GCMUtil.areEqual(arrayOfLong, this.lookupPowX2.elementAt(0)))
      return; 
    this.lookupPowX2 = new Vector(8);
    this.lookupPowX2.addElement(arrayOfLong);
  }
  
  public void exponentiateX(long paramLong, byte[] paramArrayOfbyte) {
    long[] arrayOfLong = GCMUtil.oneAsLongs();
    byte b = 0;
    while (paramLong > 0L) {
      if ((paramLong & 0x1L) != 0L) {
        ensureAvailable(b);
        GCMUtil.multiply(arrayOfLong, this.lookupPowX2.elementAt(b));
      } 
      b++;
      paramLong >>>= 1L;
    } 
    GCMUtil.asBytes(arrayOfLong, paramArrayOfbyte);
  }
  
  private void ensureAvailable(int paramInt) {
    int i = this.lookupPowX2.size() - 1;
    if (i < paramInt) {
      long[] arrayOfLong = this.lookupPowX2.elementAt(i);
      do {
        long[] arrayOfLong1 = new long[2];
        GCMUtil.square(arrayOfLong, arrayOfLong1);
        this.lookupPowX2.addElement(arrayOfLong1);
        arrayOfLong = arrayOfLong1;
      } while (++i < paramInt);
    } 
  }
}
