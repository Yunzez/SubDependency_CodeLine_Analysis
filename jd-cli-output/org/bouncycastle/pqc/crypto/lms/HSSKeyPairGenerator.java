package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class HSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
  HSSKeyGenerationParameters param;
  
  public void init(KeyGenerationParameters paramKeyGenerationParameters) {
    this.param = (HSSKeyGenerationParameters)paramKeyGenerationParameters;
  }
  
  public AsymmetricCipherKeyPair generateKeyPair() {
    HSSPrivateKeyParameters hSSPrivateKeyParameters = HSS.generateHSSKeyPair(this.param);
    return new AsymmetricCipherKeyPair(hSSPrivateKeyParameters.getPublicKey(), hSSPrivateKeyParameters);
  }
}
