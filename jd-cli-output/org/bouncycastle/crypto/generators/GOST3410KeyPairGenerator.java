package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.GOST3410KeyGenerationParameters;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.crypto.params.GOST3410PrivateKeyParameters;
import org.bouncycastle.crypto.params.GOST3410PublicKeyParameters;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

public class GOST3410KeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
  private GOST3410KeyGenerationParameters param;
  
  public void init(KeyGenerationParameters paramKeyGenerationParameters) {
    this.param = (GOST3410KeyGenerationParameters)paramKeyGenerationParameters;
  }
  
  public AsymmetricCipherKeyPair generateKeyPair() {
    GOST3410Parameters gOST3410Parameters = this.param.getParameters();
    SecureRandom secureRandom = this.param.getRandom();
    BigInteger bigInteger2 = gOST3410Parameters.getQ();
    BigInteger bigInteger1 = gOST3410Parameters.getP();
    BigInteger bigInteger3 = gOST3410Parameters.getA();
    byte b = 64;
    while (true) {
      BigInteger bigInteger4 = BigIntegers.createRandomBigInteger(256, secureRandom);
      if (bigInteger4.signum() < 1 || bigInteger4.compareTo(bigInteger2) >= 0 || WNafUtil.getNafWeight(bigInteger4) < b)
        continue; 
      BigInteger bigInteger5 = bigInteger3.modPow(bigInteger4, bigInteger1);
      return new AsymmetricCipherKeyPair(new GOST3410PublicKeyParameters(bigInteger5, gOST3410Parameters), new GOST3410PrivateKeyParameters(bigInteger4, gOST3410Parameters));
    } 
  }
}
