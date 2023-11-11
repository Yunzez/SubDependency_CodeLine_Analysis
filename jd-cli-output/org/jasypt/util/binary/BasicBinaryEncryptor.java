package org.jasypt.util.binary;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;

public final class BasicBinaryEncryptor implements BinaryEncryptor {
  private final StandardPBEByteEncryptor encryptor;
  
  public BasicBinaryEncryptor() {
    this.encryptor = new StandardPBEByteEncryptor();
    this.encryptor.setAlgorithm("PBEWithMD5AndDES");
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
