package org.bouncycastle.math.raw;

public abstract class Bits {
  public static int bitPermuteStep(int paramInt1, int paramInt2, int paramInt3) {
    int i = (paramInt1 ^ paramInt1 >>> paramInt3) & paramInt2;
    return i ^ i << paramInt3 ^ paramInt1;
  }
  
  public static long bitPermuteStep(long paramLong1, long paramLong2, int paramInt) {
    long l = (paramLong1 ^ paramLong1 >>> paramInt) & paramLong2;
    return l ^ l << paramInt ^ paramLong1;
  }
  
  public static int bitPermuteStepSimple(int paramInt1, int paramInt2, int paramInt3) {
    return (paramInt1 & paramInt2) << paramInt3 | paramInt1 >>> paramInt3 & paramInt2;
  }
  
  public static long bitPermuteStepSimple(long paramLong1, long paramLong2, int paramInt) {
    return (paramLong1 & paramLong2) << paramInt | paramLong1 >>> paramInt & paramLong2;
  }
}
