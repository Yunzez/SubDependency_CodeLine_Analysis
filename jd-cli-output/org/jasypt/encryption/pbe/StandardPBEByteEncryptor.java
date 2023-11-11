package org.jasypt.encryption.pbe;

import java.lang.reflect.Constructor;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.PBECleanablePasswordConfig;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.iv.IvGenerator;
import org.jasypt.iv.NoIvGenerator;
import org.jasypt.normalization.Normalizer;
import org.jasypt.salt.RandomSaltGenerator;
import org.jasypt.salt.SaltGenerator;

public final class StandardPBEByteEncryptor implements PBEByteCleanablePasswordEncryptor {
  public static final String DEFAULT_ALGORITHM = "PBEWithMD5AndDES";
  
  public static final int DEFAULT_KEY_OBTENTION_ITERATIONS = 1000;
  
  public static final int DEFAULT_SALT_SIZE_BYTES = 8;
  
  public static final int DEFAULT_IV_SIZE_BYTES = 16;
  
  private String algorithm = "PBEWithMD5AndDES";
  
  private String providerName = null;
  
  private Provider provider = null;
  
  private char[] password = null;
  
  private int keyObtentionIterations = 1000;
  
  private SaltGenerator saltGenerator = null;
  
  private int saltSizeBytes = 8;
  
  private IvGenerator ivGenerator = null;
  
  private int ivSizeBytes = 16;
  
  private PBEConfig config = null;
  
  private boolean algorithmSet = false;
  
  private boolean passwordSet = false;
  
  private boolean iterationsSet = false;
  
  private boolean saltGeneratorSet = false;
  
  private boolean ivGeneratorSet = false;
  
  private boolean providerNameSet = false;
  
  private boolean providerSet = false;
  
  private boolean initialized = false;
  
  private SecretKey key = null;
  
  private Cipher encryptCipher = null;
  
  private Cipher decryptCipher = null;
  
  private boolean optimizingDueFixedSalt = false;
  
  private byte[] fixedSaltInUse = null;
  
  public synchronized void setConfig(PBEConfig config) {
    CommonUtils.validateNotNull(config, "Config cannot be set null");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.config = config;
  }
  
  public synchronized void setAlgorithm(String algorithm) {
    CommonUtils.validateNotEmpty(algorithm, "Algorithm cannot be set empty");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.algorithm = algorithm;
    this.algorithmSet = true;
  }
  
  public synchronized void setPassword(String password) {
    CommonUtils.validateNotEmpty(password, "Password cannot be set empty");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    if (this.password != null)
      cleanPassword(this.password); 
    this.password = password.toCharArray();
    this.passwordSet = true;
  }
  
  public synchronized void setPasswordCharArray(char[] password) {
    CommonUtils.validateNotNull(password, "Password cannot be set null");
    CommonUtils.validateIsTrue((password.length > 0), "Password cannot be set empty");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    if (this.password != null)
      cleanPassword(this.password); 
    this.password = new char[password.length];
    System.arraycopy(password, 0, this.password, 0, password.length);
    this.passwordSet = true;
  }
  
  public synchronized void setKeyObtentionIterations(int keyObtentionIterations) {
    CommonUtils.validateIsTrue((keyObtentionIterations > 0), "Number of iterations for key obtention must be greater than zero");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.keyObtentionIterations = keyObtentionIterations;
    this.iterationsSet = true;
  }
  
  public synchronized void setSaltGenerator(SaltGenerator saltGenerator) {
    CommonUtils.validateNotNull(saltGenerator, "Salt generator cannot be set null");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.saltGenerator = saltGenerator;
    this.saltGeneratorSet = true;
  }
  
  public synchronized void setIvGenerator(IvGenerator ivGenerator) {
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.ivGenerator = ivGenerator;
    this.ivGeneratorSet = true;
  }
  
  public synchronized void setProviderName(String providerName) {
    CommonUtils.validateNotNull(providerName, "Provider name cannot be set null");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.providerName = providerName;
    this.providerNameSet = true;
  }
  
  public synchronized void setProvider(Provider provider) {
    CommonUtils.validateNotNull(provider, "Provider cannot be set null");
    if (isInitialized())
      throw new AlreadyInitializedException(); 
    this.provider = provider;
    this.providerSet = true;
  }
  
  synchronized StandardPBEByteEncryptor[] cloneAndInitializeEncryptor(int size) {
    if (isInitialized())
      throw new EncryptionInitializationException("Cannot clone encryptor if it has been already initialized"); 
    resolveConfigurationPassword();
    char[] copiedPassword = new char[this.password.length];
    System.arraycopy(this.password, 0, copiedPassword, 0, this.password.length);
    initialize();
    StandardPBEByteEncryptor[] clones = new StandardPBEByteEncryptor[size];
    clones[0] = this;
    for (int i = 1; i < size; i++) {
      StandardPBEByteEncryptor clone = new StandardPBEByteEncryptor();
      clone.setPasswordCharArray(copiedPassword);
      if (CommonUtils.isNotEmpty(this.algorithm))
        clone.setAlgorithm(this.algorithm); 
      clone.setKeyObtentionIterations(this.keyObtentionIterations);
      if (this.provider != null)
        clone.setProvider(this.provider); 
      if (this.providerName != null)
        clone.setProviderName(this.providerName); 
      if (this.saltGenerator != null)
        clone.setSaltGenerator(this.saltGenerator); 
      if (this.ivGenerator != null)
        clone.setIvGenerator(this.ivGenerator); 
      clones[i] = clone;
    } 
    cleanPassword(copiedPassword);
    return clones;
  }
  
  public boolean isInitialized() {
    return this.initialized;
  }
  
  public synchronized void initialize() {
    if (!this.initialized) {
      if (this.config != null) {
        resolveConfigurationPassword();
        String configAlgorithm = this.config.getAlgorithm();
        if (configAlgorithm != null)
          CommonUtils.validateNotEmpty(configAlgorithm, "Algorithm cannot be set empty"); 
        Integer configKeyObtentionIterations = this.config.getKeyObtentionIterations();
        if (configKeyObtentionIterations != null)
          CommonUtils.validateIsTrue((configKeyObtentionIterations.intValue() > 0), "Number of iterations for key obtention must be greater than zero"); 
        SaltGenerator configSaltGenerator = this.config.getSaltGenerator();
        IvGenerator configIvGenerator = this.config.getIvGenerator();
        String configProviderName = this.config.getProviderName();
        if (configProviderName != null)
          CommonUtils.validateNotEmpty(configProviderName, "Provider name cannot be empty"); 
        Provider configProvider = this.config.getProvider();
        this.algorithm = (this.algorithmSet || configAlgorithm == null) ? this.algorithm : configAlgorithm;
        this


          
          .keyObtentionIterations = (this.iterationsSet || configKeyObtentionIterations == null) ? this.keyObtentionIterations : configKeyObtentionIterations.intValue();
        this.saltGenerator = (this.saltGeneratorSet || configSaltGenerator == null) ? this.saltGenerator : configSaltGenerator;
        this.ivGenerator = (this.ivGeneratorSet || configIvGenerator == null) ? this.ivGenerator : configIvGenerator;
        this.providerName = (this.providerNameSet || configProviderName == null) ? this.providerName : configProviderName;
        this.provider = (this.providerSet || configProvider == null) ? this.provider : configProvider;
      } 
      if (this.saltGenerator == null)
        this.saltGenerator = new RandomSaltGenerator(); 
      if (this.ivGenerator == null)
        this.ivGenerator = new NoIvGenerator(); 
      try {
        if (this.password == null)
          throw new EncryptionInitializationException("Password not set for Password Based Encryptor"); 
        char[] normalizedPassword = Normalizer.normalizeToNfc(this.password);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(normalizedPassword);
        cleanPassword(this.password);
        cleanPassword(normalizedPassword);
        if (this.provider != null) {
          SecretKeyFactory factory = SecretKeyFactory.getInstance(this.algorithm, this.provider);
          this.key = factory.generateSecret(pbeKeySpec);
          this
            .encryptCipher = Cipher.getInstance(this.algorithm, this.provider);
          this
            .decryptCipher = Cipher.getInstance(this.algorithm, this.provider);
        } else if (this.providerName != null) {
          SecretKeyFactory factory = SecretKeyFactory.getInstance(this.algorithm, this.providerName);
          this.key = factory.generateSecret(pbeKeySpec);
          this
            .encryptCipher = Cipher.getInstance(this.algorithm, this.providerName);
          this
            .decryptCipher = Cipher.getInstance(this.algorithm, this.providerName);
        } else {
          SecretKeyFactory factory = SecretKeyFactory.getInstance(this.algorithm);
          this.key = factory.generateSecret(pbeKeySpec);
          this.encryptCipher = Cipher.getInstance(this.algorithm);
          this.decryptCipher = Cipher.getInstance(this.algorithm);
        } 
      } catch (EncryptionInitializationException e) {
        throw e;
      } catch (Throwable t) {
        throw new EncryptionInitializationException(t);
      } 
      int algorithmBlockSize = this.encryptCipher.getBlockSize();
      if (algorithmBlockSize > 0) {
        this.saltSizeBytes = algorithmBlockSize;
        this.ivSizeBytes = algorithmBlockSize;
      } 
      this.optimizingDueFixedSalt = (this.saltGenerator instanceof org.jasypt.salt.FixedSaltGenerator && this.ivGenerator instanceof NoIvGenerator);
      if (this.optimizingDueFixedSalt) {
        this
          .fixedSaltInUse = this.saltGenerator.generateSalt(this.saltSizeBytes);
        PBEParameterSpec parameterSpec = new PBEParameterSpec(this.fixedSaltInUse, this.keyObtentionIterations);
        try {
          this.encryptCipher.init(1, this.key, parameterSpec);
          this.decryptCipher.init(2, this.key, parameterSpec);
        } catch (Exception e) {
          throw new EncryptionOperationNotPossibleException();
        } 
      } 
      this.initialized = true;
    } 
  }
  
  private synchronized void resolveConfigurationPassword() {
    if (!this.initialized)
      if (this.config != null && !this.passwordSet) {
        char[] configPassword = null;
        if (this.config instanceof PBECleanablePasswordConfig) {
          configPassword = ((PBECleanablePasswordConfig)this.config).getPasswordCharArray();
        } else {
          String configPwd = this.config.getPassword();
          if (configPwd != null)
            configPassword = configPwd.toCharArray(); 
        } 
        if (configPassword != null)
          CommonUtils.validateIsTrue((configPassword.length > 0), "Password cannot be set empty"); 
        if (configPassword != null) {
          this.password = new char[configPassword.length];
          System.arraycopy(configPassword, 0, this.password, 0, configPassword.length);
          this.passwordSet = true;
          cleanPassword(configPassword);
        } 
        if (this.config instanceof PBECleanablePasswordConfig)
          ((PBECleanablePasswordConfig)this.config).cleanPassword(); 
      }  
  }
  
  private static void cleanPassword(char[] password) {
    if (password != null)
      synchronized (password) {
        int pwdLength = password.length;
        for (int i = 0; i < pwdLength; i++)
          password[i] = Character.MIN_VALUE; 
      }  
  }
  
  public byte[] encrypt(byte[] message) throws EncryptionOperationNotPossibleException {
    if (message == null)
      return null; 
    if (!isInitialized())
      initialize(); 
    try {
      byte[] salt, encryptedMessage, iv = null;
      if (this.optimizingDueFixedSalt) {
        salt = this.fixedSaltInUse;
        synchronized (this.encryptCipher) {
          encryptedMessage = this.encryptCipher.doFinal(message);
        } 
      } else {
        salt = this.saltGenerator.generateSalt(this.saltSizeBytes);
        iv = this.ivGenerator.generateIv(this.ivSizeBytes);
        PBEParameterSpec parameterSpec = buildPBEParameterSpec(salt, iv);
        synchronized (this.encryptCipher) {
          this.encryptCipher.init(1, this.key, parameterSpec);
          encryptedMessage = this.encryptCipher.doFinal(message);
        } 
      } 
      if (this.ivGenerator.includePlainIvInEncryptionResults())
        encryptedMessage = CommonUtils.appendArrays(iv, encryptedMessage); 
      if (this.saltGenerator.includePlainSaltInEncryptionResults())
        encryptedMessage = CommonUtils.appendArrays(salt, encryptedMessage); 
      return encryptedMessage;
    } catch (InvalidKeyException e) {
      handleInvalidKeyException(e);
      throw new EncryptionOperationNotPossibleException();
    } catch (Exception e) {
      throw new EncryptionOperationNotPossibleException();
    } 
  }
  
  public byte[] decrypt(byte[] encryptedMessage) throws EncryptionOperationNotPossibleException {
    if (encryptedMessage == null)
      return null; 
    if (!isInitialized())
      initialize(); 
    if (this.saltGenerator.includePlainSaltInEncryptionResults() && this.ivGenerator
      .includePlainIvInEncryptionResults()) {
      if (encryptedMessage.length <= this.saltSizeBytes + this.ivSizeBytes)
        throw new EncryptionOperationNotPossibleException(); 
    } else if (this.saltGenerator.includePlainSaltInEncryptionResults()) {
      if (encryptedMessage.length <= this.saltSizeBytes)
        throw new EncryptionOperationNotPossibleException(); 
    } else if (this.ivGenerator.includePlainIvInEncryptionResults()) {
      if (encryptedMessage.length <= this.ivSizeBytes)
        throw new EncryptionOperationNotPossibleException(); 
    } 
    try {
      byte[] decryptedMessage, salt = null;
      byte[] encryptedMessageKernel = null;
      if (this.saltGenerator.includePlainSaltInEncryptionResults()) {
        int saltStart = 0;
        int saltSize = (this.saltSizeBytes < encryptedMessage.length) ? this.saltSizeBytes : encryptedMessage.length;
        int encMesKernelStart = (this.saltSizeBytes < encryptedMessage.length) ? this.saltSizeBytes : encryptedMessage.length;
        int encMesKernelSize = (this.saltSizeBytes < encryptedMessage.length) ? (encryptedMessage.length - this.saltSizeBytes) : 0;
        salt = new byte[saltSize];
        encryptedMessageKernel = new byte[encMesKernelSize];
        System.arraycopy(encryptedMessage, 0, salt, 0, saltSize);
        System.arraycopy(encryptedMessage, encMesKernelStart, encryptedMessageKernel, 0, encMesKernelSize);
      } else if (!this.optimizingDueFixedSalt) {
        salt = this.saltGenerator.generateSalt(this.saltSizeBytes);
        encryptedMessageKernel = encryptedMessage;
      } else {
        salt = this.fixedSaltInUse;
        encryptedMessageKernel = encryptedMessage;
      } 
      byte[] iv = null;
      byte[] finalEncryptedMessageKernel = null;
      if (this.ivGenerator.includePlainIvInEncryptionResults()) {
        int ivStart = 0;
        int ivSize = (this.ivSizeBytes < encryptedMessageKernel.length) ? this.ivSizeBytes : encryptedMessageKernel.length;
        int encMesKernelStart = (this.ivSizeBytes < encryptedMessageKernel.length) ? this.ivSizeBytes : encryptedMessageKernel.length;
        int encMesKernelSize = (this.ivSizeBytes < encryptedMessageKernel.length) ? (encryptedMessageKernel.length - this.ivSizeBytes) : 0;
        iv = new byte[ivSize];
        finalEncryptedMessageKernel = new byte[encMesKernelSize];
        System.arraycopy(encryptedMessageKernel, 0, iv, 0, ivSize);
        System.arraycopy(encryptedMessageKernel, encMesKernelStart, finalEncryptedMessageKernel, 0, encMesKernelSize);
      } else {
        iv = this.ivGenerator.generateIv(this.ivSizeBytes);
        finalEncryptedMessageKernel = encryptedMessageKernel;
      } 
      if (this.optimizingDueFixedSalt) {
        synchronized (this.decryptCipher) {
          decryptedMessage = this.decryptCipher.doFinal(finalEncryptedMessageKernel);
        } 
      } else {
        PBEParameterSpec parameterSpec = buildPBEParameterSpec(salt, iv);
        synchronized (this.decryptCipher) {
          this.decryptCipher.init(2, this.key, parameterSpec);
          decryptedMessage = this.decryptCipher.doFinal(finalEncryptedMessageKernel);
        } 
      } 
      return decryptedMessage;
    } catch (InvalidKeyException e) {
      handleInvalidKeyException(e);
      throw new EncryptionOperationNotPossibleException();
    } catch (Exception e) {
      throw new EncryptionOperationNotPossibleException();
    } 
  }
  
  private PBEParameterSpec buildPBEParameterSpec(byte[] salt, byte[] iv) {
    PBEParameterSpec parameterSpec;
    try {
      Class[] parameters = { byte[].class, int.class, AlgorithmParameterSpec.class };
      Constructor<PBEParameterSpec> java8Constructor = PBEParameterSpec.class.getConstructor(parameters);
      Object[] parameterValues = { salt, Integer.valueOf(this.keyObtentionIterations), new IvParameterSpec(iv) };
      parameterSpec = java8Constructor.newInstance(parameterValues);
    } catch (Exception e) {
      parameterSpec = new PBEParameterSpec(salt, this.keyObtentionIterations);
    } 
    return parameterSpec;
  }
  
  private void handleInvalidKeyException(InvalidKeyException e) {
    if (e.getMessage() != null && e
      .getMessage().toUpperCase().indexOf("KEY SIZE") != -1)
      throw new EncryptionOperationNotPossibleException("Encryption raised an exception. A possible cause is you are using strong encryption algorithms and you have not installed the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files in this Java Virtual Machine"); 
  }
}
