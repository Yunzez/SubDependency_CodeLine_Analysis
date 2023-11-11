package org.jasypt.digest.config;

import java.security.Provider;
import org.jasypt.salt.SaltGenerator;

public interface DigesterConfig {
  String getAlgorithm();
  
  Integer getSaltSizeBytes();
  
  Integer getIterations();
  
  SaltGenerator getSaltGenerator();
  
  String getProviderName();
  
  Provider getProvider();
  
  Boolean getInvertPositionOfSaltInMessageBeforeDigesting();
  
  Boolean getInvertPositionOfPlainSaltInEncryptionResults();
  
  Boolean getUseLenientSaltSizeCheck();
  
  Integer getPoolSize();
}
