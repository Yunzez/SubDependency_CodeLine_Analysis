package org.jasypt.util.password;

public interface PasswordEncryptor {
  String encryptPassword(String paramString);
  
  boolean checkPassword(String paramString1, String paramString2);
}
