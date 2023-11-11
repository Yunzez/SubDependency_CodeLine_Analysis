package org.jasypt.iv;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.jasypt.exceptions.EncryptionInitializationException;

public class RandomIvGenerator implements IvGenerator {
  public static final String DEFAULT_SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
  
  private final SecureRandom random;
  
  public RandomIvGenerator() {
    this("SHA1PRNG");
  }
  
  public RandomIvGenerator(String secureRandomAlgorithm) {
    try {
      this.random = SecureRandom.getInstance(secureRandomAlgorithm);
    } catch (NoSuchAlgorithmException e) {
      throw new EncryptionInitializationException(e);
    } 
  }
  
  public byte[] generateIv(int lengthBytes) {
    byte[] iv = new byte[lengthBytes];
    synchronized (this.random) {
      this.random.nextBytes(iv);
    } 
    return iv;
  }
  
  public boolean includePlainIvInEncryptionResults() {
    return true;
  }
}
