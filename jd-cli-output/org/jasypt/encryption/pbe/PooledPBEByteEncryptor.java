package org.jasypt.encryption.pbe;

import java.security.Provider;
import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.iv.IvGenerator;
import org.jasypt.salt.SaltGenerator;

public final class PooledPBEByteEncryptor implements PBEByteCleanablePasswordEncryptor {
  private final StandardPBEByteEncryptor firstEncryptor;
  
  private PBEConfig config = null;
  
  private int poolSize = 0;
  
  private boolean poolSizeSet = false;
  
  private StandardPBEByteEncryptor[] pool;
  
  private int roundRobin = 0;
  
  private boolean initialized = false;
  
  public PooledPBEByteEncryptor() {
    this.firstEncryptor = new StandardPBEByteEncryptor();
  }
  
  public synchronized void setConfig(PBEConfig config) {
    this.firstEncryptor.setConfig(config);
    this.config = config;
  }
  
  public synchronized void setAlgorithm(String algorithm) {
    this.firstEncryptor.setAlgorithm(algorithm);
  }
  
  public synchronized void setPassword(String password) {
    this.firstEncryptor.setPassword(password);
  }
  
  public synchronized void setPasswordCharArray(char[] password) {
    this.firstEncryptor.setPasswordCharArray(password);
  }
  
  public synchronized void setKeyObtentionIterations(int keyObtentionIterations) {
    this.firstEncryptor.setKeyObtentionIterations(keyObtentionIterations);
  }
  
  public synchronized void setSaltGenerator(SaltGenerator saltGenerator) {
    this.firstEncryptor.setSaltGenerator(saltGenerator);
  }
  
  public synchronized void setIvGenerator(IvGenerator ivGenerator) {
    this.firstEncryptor.setIvGenerator(ivGenerator);
  }
  
  public synchronized void setProviderName(String providerName) {
    this.firstEncryptor.setProviderName(providerName);
  }
  
  public synchronized void setProvider(Provider provider) {
    this.firstEncryptor.setProvider(provider);
  }
  
  public synchronized void setPoolSize(int poolSize) {
    CommonUtils.validateIsTrue((poolSize > 0), "Pool size be > 0");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.poolSize = poolSize;
    this.poolSizeSet = true;
  }
  
  public boolean isInitialized() {
    return this.initialized;
  }
  
  public synchronized void initialize() {
    if (!this.initialized) {
      if (this.config != null) {
        Integer configPoolSize = this.config.getPoolSize();
        this
          
          .poolSize = (this.poolSizeSet || configPoolSize == null) ? this.poolSize : configPoolSize.intValue();
      } 
      if (this.poolSize <= 0)
        throw new IllegalArgumentException("Pool size must be set and > 0"); 
      this.pool = this.firstEncryptor.cloneAndInitializeEncryptor(this.poolSize);
      this.initialized = true;
    } 
  }
  
  public byte[] encrypt(byte[] message) throws EncryptionOperationNotPossibleException {
    int poolPosition;
    if (!isInitialized())
      initialize(); 
    synchronized (this) {
      poolPosition = this.roundRobin;
      this.roundRobin = (this.roundRobin + 1) % this.poolSize;
    } 
    return this.pool[poolPosition].encrypt(message);
  }
  
  public byte[] decrypt(byte[] encryptedMessage) throws EncryptionOperationNotPossibleException {
    int poolPosition;
    if (!isInitialized())
      initialize(); 
    synchronized (this) {
      poolPosition = this.roundRobin;
      this.roundRobin = (this.roundRobin + 1) % this.poolSize;
    } 
    return this.pool[poolPosition].decrypt(encryptedMessage);
  }
}
