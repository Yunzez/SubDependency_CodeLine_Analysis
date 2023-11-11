package org.bouncycastle.pqc.crypto.sphincsplus;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;

public class SPHINCSPlusKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
  private SecureRandom random;
  
  private SPHINCSPlusParameters parameters;
  
  public void init(KeyGenerationParameters paramKeyGenerationParameters) {
    this.random = paramKeyGenerationParameters.getRandom();
    this.parameters = ((SPHINCSPlusKeyGenerationParameters)paramKeyGenerationParameters).getParameters();
  }
  
  public AsymmetricCipherKeyPair generateKeyPair() {
    SPHINCSPlusEngine sPHINCSPlusEngine = this.parameters.getEngine();
    SK sK = new SK(sec_rand(sPHINCSPlusEngine.N), sec_rand(sPHINCSPlusEngine.N));
    byte[] arrayOfByte = sec_rand(sPHINCSPlusEngine.N);
    PK pK = new PK(arrayOfByte, (new HT(sPHINCSPlusEngine, sK.seed, arrayOfByte)).htPubKey);
    return new AsymmetricCipherKeyPair(new SPHINCSPlusPublicKeyParameters(this.parameters, pK), new SPHINCSPlusPrivateKeyParameters(this.parameters, sK, pK));
  }
  
  private byte[] sec_rand(int paramInt) {
    byte[] arrayOfByte = new byte[paramInt];
    this.random.nextBytes(arrayOfByte);
    return arrayOfByte;
  }
}
