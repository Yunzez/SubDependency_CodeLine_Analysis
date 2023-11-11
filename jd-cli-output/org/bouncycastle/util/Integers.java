package org.bouncycastle.util;

public class Integers {
  public static final int BYTES = 4;
  
  public static final int SIZE = 32;
  
  public static int numberOfLeadingZeros(int paramInt) {
    return Integer.numberOfLeadingZeros(paramInt);
  }
  
  public static int numberOfTrailingZeros(int paramInt) {
    return Integer.numberOfTrailingZeros(paramInt);
  }
  
  public static int reverse(int paramInt) {
    return Integer.reverse(paramInt);
  }
  
  public static int reverseBytes(int paramInt) {
    return Integer.reverseBytes(paramInt);
  }
  
  public static int rotateLeft(int paramInt1, int paramInt2) {
    return Integer.rotateLeft(paramInt1, paramInt2);
  }
  
  public static int rotateRight(int paramInt1, int paramInt2) {
    return Integer.rotateRight(paramInt1, paramInt2);
  }
  
  public static Integer valueOf(int paramInt) {
    return Integer.valueOf(paramInt);
  }
}
