package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Arrays;

public class FPEParameterSpec implements AlgorithmParameterSpec {
  private final int radix;
  
  private final byte[] tweak;
  
  private final boolean useInverse;
  
  public FPEParameterSpec(int paramInt, byte[] paramArrayOfbyte) {
    this(paramInt, paramArrayOfbyte, false);
  }
  
  public FPEParameterSpec(int paramInt, byte[] paramArrayOfbyte, boolean paramBoolean) {
    this.radix = paramInt;
    this.tweak = Arrays.clone(paramArrayOfbyte);
    this.useInverse = paramBoolean;
  }
  
  public int getRadix() {
    return this.radix;
  }
  
  public byte[] getTweak() {
    return Arrays.clone(this.tweak);
  }
  
  public boolean isUsingInverseFunction() {
    return this.useInverse;
  }
}
