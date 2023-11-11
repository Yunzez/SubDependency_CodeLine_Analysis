package org.jasypt.util.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;

public final class AES256TextEncryptor implements TextEncryptor {
  private final StandardPBEStringEncryptor encryptor;
  
  public AES256TextEncryptor() {
    this.encryptor = new StandardPBEStringEncryptor();
    this.encryptor.setAlgorithm("PBEWithHMACSHA512AndAES_256");
    this.encryptor.setIvGenerator(new RandomIvGenerator());
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
