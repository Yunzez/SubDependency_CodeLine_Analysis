package org.jasypt.util.binary;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.iv.RandomIvGenerator;

public final class AES256BinaryEncryptor implements BinaryEncryptor {
  private final StandardPBEByteEncryptor encryptor;
  
  public AES256BinaryEncryptor() {
    this.encryptor = new StandardPBEByteEncryptor();
    this.encryptor.setAlgorithm("PBEWithHMACSHA512AndAES_256");
    this.encryptor.setIvGenerator(new RandomIvGenerator());
  }
  
  public void setPassword(String password) {
    this.encryptor.setPassword(password);
  }
  
  public void setPasswordCharArray(char[] password) {
    this.encryptor.setPasswordCharArray(password);
  }
  
  public byte[] encrypt(byte[] binary) {
    return this.encryptor.encrypt(binary);
  }
  
  public byte[] decrypt(byte[] encryptedBinary) {
    return this.encryptor.decrypt(encryptedBinary);
  }
}
