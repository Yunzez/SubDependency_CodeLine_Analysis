package org.jasypt.encryption.pbe.config;

import java.security.Provider;
import org.jasypt.iv.IvGenerator;
import org.jasypt.salt.SaltGenerator;

public interface PBEConfig {
  String getAlgorithm();
  
  String getPassword();
  
  Integer getKeyObtentionIterations();
  
  SaltGenerator getSaltGenerator();
  
  IvGenerator getIvGenerator();
  
  String getProviderName();
  
  Provider getProvider();
  
  Integer getPoolSize();
}
