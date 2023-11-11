package org.jasypt.util.text;

public interface TextEncryptor {
  String encrypt(String paramString);
  
  String decrypt(String paramString);
}
