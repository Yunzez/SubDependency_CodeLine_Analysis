package org.jasypt.encryption.pbe.config;

public interface PBECleanablePasswordConfig {
  char[] getPasswordCharArray();
  
  void cleanPassword();
}
