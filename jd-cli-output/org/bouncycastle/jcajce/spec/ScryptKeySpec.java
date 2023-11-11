package org.bouncycastle.jcajce.spec;

import java.security.spec.KeySpec;
import org.bouncycastle.util.Arrays;

public class ScryptKeySpec implements KeySpec {
  private final char[] password;
  
  private final byte[] salt;
  
  private final int costParameter;
  
  private final int blockSize;
  
  private final int parallelizationParameter;
  
  private final int keySize;
  
  public ScryptKeySpec(char[] paramArrayOfchar, byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3, int paramInt4) {
    this.password = paramArrayOfchar;
    this.salt = Arrays.clone(paramArrayOfbyte);
    this.costParameter = paramInt1;
    this.blockSize = paramInt2;
    this.parallelizationParameter = paramInt3;
    this.keySize = paramInt4;
  }
  
  public char[] getPassword() {
    return this.password;
  }
  
  public byte[] getSalt() {
    return Arrays.clone(this.salt);
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
  
  public int getKeyLength() {
    return this.keySize;
  }
}
