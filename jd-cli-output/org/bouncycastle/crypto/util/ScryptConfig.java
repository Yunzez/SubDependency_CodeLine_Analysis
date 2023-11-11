package org.bouncycastle.crypto.util;

import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;

public class ScryptConfig extends PBKDFConfig {
  private final int costParameter;
  
  private final int blockSize;
  
  private final int parallelizationParameter;
  
  private final int saltLength;
  
  private ScryptConfig(Builder paramBuilder) {
    super(MiscObjectIdentifiers.id_scrypt);
    this.costParameter = paramBuilder.costParameter;
    this.blockSize = paramBuilder.blockSize;
    this.parallelizationParameter = paramBuilder.parallelizationParameter;
    this.saltLength = paramBuilder.saltLength;
  }
  
  public int getCostParameter() {
    return this.costParameter;
  }
  
  public int getBlockSize() {
    return this.blockSize;
  }
  
  public int getParallelizationParameter() {
    return this.parallelizationParameter;
  }
  
  public int getSaltLength() {
    return this.saltLength;
  }
  
  public static class Builder {
    private final int costParameter;
    
    private final int blockSize;
    
    private final int parallelizationParameter;
    
    private int saltLength = 16;
    
    public Builder(int param1Int1, int param1Int2, int param1Int3) {
      if (param1Int1 <= 1 || !isPowerOf2(param1Int1))
        throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2"); 
      this.costParameter = param1Int1;
      this.blockSize = param1Int2;
      this.parallelizationParameter = param1Int3;
    }
    
    public Builder withSaltLength(int param1Int) {
      this.saltLength = param1Int;
      return this;
    }
    
    public ScryptConfig build() {
      return new ScryptConfig(this);
    }
    
    private static boolean isPowerOf2(int param1Int) {
      return ((param1Int & param1Int - 1) == 0);
    }
  }
}
