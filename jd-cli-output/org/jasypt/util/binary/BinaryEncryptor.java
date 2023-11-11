package org.jasypt.util.binary;

public interface BinaryEncryptor {
  byte[] encrypt(byte[] paramArrayOfbyte);
  
  byte[] decrypt(byte[] paramArrayOfbyte);
}
