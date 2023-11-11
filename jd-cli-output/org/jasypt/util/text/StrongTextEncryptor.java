package org.jasypt.util.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

public final class StrongTextEncryptor implements TextEncryptor {
  private final StandardPBEStringEncryptor encryptor;
  
  public StrongTextEncryptor() {
    this.encryptor = new StandardPBEStringEncryptor();
    this.encryptor.setAlgorithm("PBEWithMD5AndTripleDES");
  }
  
  public void setPassword(String password) {
    this.encryptor.setPassword(password);
  }
  
  public void setPasswordCharArray(char[] password) {
    this.encryptor.setPasswordCharArray(password);
  }
  
  public String encrypt(String message) {
    return this.encryptor.encrypt(message);
  }
  
  public String decrypt(String encryptedMessage) {
    return this.encryptor.decrypt(encryptedMessage);
  }
}
