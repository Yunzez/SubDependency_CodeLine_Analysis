package org.jasypt.util.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;

public final class BasicTextEncryptor implements TextEncryptor {
  private final StandardPBEStringEncryptor encryptor;
  
  public BasicTextEncryptor() {
    this.encryptor = new StandardPBEStringEncryptor();
    this.encryptor.setAlgorithm("PBEWithMD5AndDES");
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
