package org.bouncycastle.pqc.crypto.lms;

public class LMSParameters {
  private final LMSigParameters lmSigParam;
  
  private final LMOtsParameters lmOTSParam;
  
  public LMSParameters(LMSigParameters paramLMSigParameters, LMOtsParameters paramLMOtsParameters) {
    this.lmSigParam = paramLMSigParameters;
    this.lmOTSParam = paramLMOtsParameters;
  }
  
  public LMSigParameters getLMSigParam() {
    return this.lmSigParam;
  }
  
  public LMOtsParameters getLMOTSParam() {
    return this.lmOTSParam;
  }
}
