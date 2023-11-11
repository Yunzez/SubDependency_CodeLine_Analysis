package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class LMSKeyGenerationParameters extends KeyGenerationParameters {
  private final LMSParameters lmsParameters;
  
  public LMSKeyGenerationParameters(LMSParameters paramLMSParameters, SecureRandom paramSecureRandom) {
    super(paramSecureRandom, LmsUtils.calculateStrength(paramLMSParameters));
    this.lmsParameters = paramLMSParameters;
  }
  
  public LMSParameters getParameters() {
    return this.lmsParameters;
  }
}
