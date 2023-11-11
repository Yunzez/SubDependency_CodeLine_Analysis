package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class LMSHSSKeyGenParameterSpec implements AlgorithmParameterSpec {
  private final LMSKeyGenParameterSpec[] specs;
  
  public LMSHSSKeyGenParameterSpec(LMSKeyGenParameterSpec... paramVarArgs) {
    if (paramVarArgs.length == 0)
      throw new IllegalArgumentException("at least one LMSKeyGenParameterSpec required"); 
    this.specs = (LMSKeyGenParameterSpec[])paramVarArgs.clone();
  }
  
  public LMSKeyGenParameterSpec[] getLMSSpecs() {
    return (LMSKeyGenParameterSpec[])this.specs.clone();
  }
}
