package org.jasypt.salt;

public interface SaltGenerator {
  byte[] generateSalt(int paramInt);
  
  boolean includePlainSaltInEncryptionResults();
}
