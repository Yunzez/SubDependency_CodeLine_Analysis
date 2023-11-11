package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

public class LMSHSSParameterSpec implements AlgorithmParameterSpec {
  private final LMSParameterSpec[] specs;
  
  public LMSHSSParameterSpec(LMSParameterSpec[] paramArrayOfLMSParameterSpec) {
    this.specs = (LMSParameterSpec[])paramArrayOfLMSParameterSpec.clone();
  }
  
  public LMSParameterSpec[] getLMSSpecs() {
    return (LMSParameterSpec[])this.specs.clone();
  }
}
