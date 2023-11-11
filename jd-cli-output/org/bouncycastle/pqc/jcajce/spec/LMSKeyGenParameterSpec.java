package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

public class LMSKeyGenParameterSpec implements AlgorithmParameterSpec {
  private final LMSigParameters lmSigParams;
  
  private final LMOtsParameters lmOtsParameters;
  
  public LMSKeyGenParameterSpec(LMSigParameters paramLMSigParameters, LMOtsParameters paramLMOtsParameters) {
    this.lmSigParams = paramLMSigParameters;
    this.lmOtsParameters = paramLMOtsParameters;
  }
  
  public LMSigParameters getSigParams() {
    return this.lmSigParams;
  }
  
  public LMOtsParameters getOtsParams() {
    return this.lmOtsParameters;
  }
}
