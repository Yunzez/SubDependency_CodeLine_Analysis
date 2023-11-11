package org.bouncycastle.crypto.params;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class X448KeyGenerationParameters extends KeyGenerationParameters {
  public X448KeyGenerationParameters(SecureRandom paramSecureRandom) {
    super(paramSecureRandom, 448);
  }
}
