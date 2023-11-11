package META-INF.versions.9.org.bouncycastle.crypto;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

public class KeyGenerationParameters {
  private SecureRandom random;
  
  private int strength;
  
  public KeyGenerationParameters(SecureRandom paramSecureRandom, int paramInt) {
    this.random = CryptoServicesRegistrar.getSecureRandom(paramSecureRandom);
    this.strength = paramInt;
  }
  
  public SecureRandom getRandom() {
    return this.random;
  }
  
  public int getStrength() {
    return this.strength;
  }
}
