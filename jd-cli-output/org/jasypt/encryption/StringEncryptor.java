package org.jasypt.encryption;

public interface StringEncryptor {
  String encrypt(String paramString);
  
  String decrypt(String paramString);
}
