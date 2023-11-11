package org.bouncycastle.util;

public class Longs {
  public static final int BYTES = 8;
  
  public static final int SIZE = 64;
  
  public static int numberOfLeadingZeros(long paramLong) {
    return Long.numberOfLeadingZeros(paramLong);
  }
  
  public static int numberOfTrailingZeros(long paramLong) {
    return Long.numberOfTrailingZeros(paramLong);
  }
  
  public static long reverse(long paramLong) {
    return Long.reverse(paramLong);
  }
  
  public static long reverseBytes(long paramLong) {
    return Long.reverseBytes(paramLong);
  }
  
  public static long rotateLeft(long paramLong, int paramInt) {
    return Long.rotateLeft(paramLong, paramInt);
  }
  
  public static long rotateRight(long paramLong, int paramInt) {
    return Long.rotateRight(paramLong, paramInt);
  }
  
  public static Long valueOf(long paramLong) {
    return Long.valueOf(paramLong);
  }
}
