package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class QTESLAKeyGenerationParameters extends KeyGenerationParameters {
  private final int securityCategory;
  
  public QTESLAKeyGenerationParameters(int paramInt, SecureRandom paramSecureRandom) {
    super(paramSecureRandom, -1);
    QTESLASecurityCategory.getPrivateSize(paramInt);
    this.securityCategory = paramInt;
  }
  
  public int getSecurityCategory() {
    return this.securityCategory;
  }
}
