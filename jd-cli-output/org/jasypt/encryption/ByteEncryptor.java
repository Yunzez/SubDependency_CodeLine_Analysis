package org.jasypt.encryption;

public interface ByteEncryptor {
  byte[] encrypt(byte[] paramArrayOfbyte);
  
  byte[] decrypt(byte[] paramArrayOfbyte);
}
