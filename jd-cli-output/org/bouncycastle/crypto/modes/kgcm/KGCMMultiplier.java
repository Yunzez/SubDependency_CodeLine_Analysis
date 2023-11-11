package org.bouncycastle.crypto.modes.kgcm;

public interface KGCMMultiplier {
  void init(long[] paramArrayOflong);
  
  void multiplyH(long[] paramArrayOflong);
}
