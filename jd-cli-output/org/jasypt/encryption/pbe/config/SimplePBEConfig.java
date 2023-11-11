package org.jasypt.encryption.pbe.config;

import java.security.Provider;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.PasswordAlreadyCleanedException;
import org.jasypt.iv.IvGenerator;
import org.jasypt.salt.SaltGenerator;

public class SimplePBEConfig implements PBEConfig, PBECleanablePasswordConfig {
  private String algorithm = null;
  
  private char[] password = null;
  
  private Integer keyObtentionIterations = null;
  
  private SaltGenerator saltGenerator = null;
  
  private IvGenerator ivGenerator = null;
  
  private String providerName = null;
  
  private Provider provider = null;
  
  private Integer poolSize = null;
  
  private boolean passwordCleaned = false;
  
  public void setAlgorithm(String algorithm) {
    this.algorithm = algorithm;
  }
  
  public void setPassword(String password) {
    if (this.password != null)
      cleanPassword(); 
    if (password == null) {
      this.password = null;
    } else {
      this.password = password.toCharArray();
    } 
  }
  
  public void setPasswordCharArray(char[] password) {
    if (this.password != null)
      cleanPassword(); 
    if (password == null) {
      this.password = null;
    } else {
      this.password = new char[password.length];
      System.arraycopy(password, 0, this.password, 0, password.length);
    } 
  }
  
  public void setKeyObtentionIterations(Integer keyObtentionIterations) {
    this.keyObtentionIterations = keyObtentionIterations;
  }
  
  public void setKeyObtentionIterations(String keyObtentionIterations) {
    if (keyObtentionIterations != null) {
      try {
        this.keyObtentionIterations = new Integer(keyObtentionIterations);
      } catch (NumberFormatException e) {
        throw new EncryptionInitializationException(e);
      } 
    } else {
      this.keyObtentionIterations = null;
    } 
  }
  
  public void setSaltGenerator(SaltGenerator saltGenerator) {
    this.saltGenerator = saltGenerator;
  }
  
  public void setSaltGeneratorClassName(String saltGeneratorClassName) {
    if (saltGeneratorClassName != null) {
      try {
        Class<?> saltGeneratorClass = Thread.currentThread().getContextClassLoader().loadClass(saltGeneratorClassName);
        this
          .saltGenerator = (SaltGenerator)saltGeneratorClass.newInstance();
      } catch (Exception e) {
        throw new EncryptionInitializationException(e);
      } 
    } else {
      this.saltGenerator = null;
    } 
  }
  
  public void setIvGenerator(IvGenerator ivGenerator) {
    this.ivGenerator = ivGenerator;
  }
  
  public void setIvGeneratorClassName(String ivGeneratorClassName) {
    if (ivGeneratorClassName != null) {
      try {
        Class<?> ivGeneratorClass = Thread.currentThread().getContextClassLoader().loadClass(ivGeneratorClassName);
        this
          .ivGenerator = (IvGenerator)ivGeneratorClass.newInstance();
      } catch (Exception e) {
        throw new EncryptionInitializationException(e);
      } 
    } else {
      this.ivGenerator = null;
    } 
  }
  
  public void setProviderName(String providerName) {
    this.providerName = providerName;
  }
  
  public void setProvider(Provider provider) {
    this.provider = provider;
  }
  
  public void setProviderClassName(String providerClassName) {
    if (providerClassName != null) {
      try {
        Class<?> providerClass = Thread.currentThread().getContextClassLoader().loadClass(providerClassName);
        this.provider = (Provider)providerClass.newInstance();
      } catch (Exception e) {
        throw new EncryptionInitializationException(e);
      } 
    } else {
      this.provider = null;
    } 
  }
  
  public void setPoolSize(Integer poolSize) {
    this.poolSize = poolSize;
  }
  
  public void setPoolSize(String poolSize) {
    if (poolSize != null) {
      try {
        this.poolSize = new Integer(poolSize);
      } catch (NumberFormatException e) {
        throw new EncryptionInitializationException(e);
      } 
    } else {
      this.poolSize = null;
    } 
  }
  
  public String getAlgorithm() {
    return this.algorithm;
  }
  
  public String getPassword() {
    if (this.passwordCleaned)
      throw new PasswordAlreadyCleanedException(); 
    return new String(this.password);
  }
  
  public char[] getPasswordCharArray() {
    if (this.passwordCleaned)
      throw new PasswordAlreadyCleanedException(); 
    char[] result = new char[this.password.length];
    System.arraycopy(this.password, 0, result, 0, this.password.length);
    return result;
  }
  
  public Integer getKeyObtentionIterations() {
    return this.keyObtentionIterations;
  }
  
  public SaltGenerator getSaltGenerator() {
    return this.saltGenerator;
  }
  
  public IvGenerator getIvGenerator() {
    return this.ivGenerator;
  }
  
  public String getProviderName() {
    return this.providerName;
  }
  
  public Provider getProvider() {
    return this.provider;
  }
  
  public Integer getPoolSize() {
    return this.poolSize;
  }
  
  public void cleanPassword() {
    if (this.password != null) {
      int pwdLength = this.password.length;
      for (int i = 0; i < pwdLength; i++)
        this.password[i] = Character.MIN_VALUE; 
      this.password = new char[0];
    } 
    this.passwordCleaned = true;
  }
}
