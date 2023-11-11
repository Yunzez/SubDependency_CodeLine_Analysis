package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

public class ECKeyPairGenerator implements AsymmetricCipherKeyPairGenerator, ECConstants {
  ECDomainParameters params;
  
  SecureRandom random;
  
  public void init(KeyGenerationParameters paramKeyGenerationParameters) {
    ECKeyGenerationParameters eCKeyGenerationParameters = (ECKeyGenerationParameters)paramKeyGenerationParameters;
    this.random = eCKeyGenerationParameters.getRandom();
    this.params = eCKeyGenerationParameters.getDomainParameters();
  }
  
  public AsymmetricCipherKeyPair generateKeyPair() {
    BigInteger bigInteger = this.params.getN();
    int i = bigInteger.bitLength();
    int j = i >>> 2;
    while (true) {
      BigInteger bigInteger1 = BigIntegers.createRandomBigInteger(i, this.random);
      if (bigInteger1.compareTo(ONE) < 0 || bigInteger1.compareTo(bigInteger) >= 0 || WNafUtil.getNafWeight(bigInteger1) < j)
        continue; 
      ECPoint eCPoint = createBasePointMultiplier().multiply(this.params.getG(), bigInteger1);
      return new AsymmetricCipherKeyPair(new ECPublicKeyParameters(eCPoint, this.params), new ECPrivateKeyParameters(bigInteger1, this.params));
    } 
  }
  
  protected ECMultiplier createBasePointMultiplier() {
    return new FixedPointCombMultiplier();
  }
}
