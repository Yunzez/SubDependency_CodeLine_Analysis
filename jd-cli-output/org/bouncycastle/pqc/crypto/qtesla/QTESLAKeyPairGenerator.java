package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public final class QTESLAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
  private int securityCategory;
  
  private SecureRandom secureRandom;
  
  public void init(KeyGenerationParameters paramKeyGenerationParameters) {
    QTESLAKeyGenerationParameters qTESLAKeyGenerationParameters = (QTESLAKeyGenerationParameters)paramKeyGenerationParameters;
    this.secureRandom = qTESLAKeyGenerationParameters.getRandom();
    this.securityCategory = qTESLAKeyGenerationParameters.getSecurityCategory();
  }
  
  public AsymmetricCipherKeyPair generateKeyPair() {
    byte[] arrayOfByte1 = allocatePrivate(this.securityCategory);
    byte[] arrayOfByte2 = allocatePublic(this.securityCategory);
    switch (this.securityCategory) {
      case 5:
        QTesla1p.generateKeyPair(arrayOfByte2, arrayOfByte1, this.secureRandom);
        return new AsymmetricCipherKeyPair(new QTESLAPublicKeyParameters(this.securityCategory, arrayOfByte2), new QTESLAPrivateKeyParameters(this.securityCategory, arrayOfByte1));
      case 6:
        QTesla3p.generateKeyPair(arrayOfByte2, arrayOfByte1, this.secureRandom);
        return new AsymmetricCipherKeyPair(new QTESLAPublicKeyParameters(this.securityCategory, arrayOfByte2), new QTESLAPrivateKeyParameters(this.securityCategory, arrayOfByte1));
    } 
    throw new IllegalArgumentException("unknown security category: " + this.securityCategory);
  }
  
  private byte[] allocatePrivate(int paramInt) {
    return new byte[QTESLASecurityCategory.getPrivateSize(paramInt)];
  }
  
  private byte[] allocatePublic(int paramInt) {
    return new byte[QTESLASecurityCategory.getPublicSize(paramInt)];
  }
}
