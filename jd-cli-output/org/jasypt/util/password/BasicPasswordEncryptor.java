package org.jasypt.util.password;

import org.jasypt.digest.StandardStringDigester;

public final class BasicPasswordEncryptor implements PasswordEncryptor {
  private final StandardStringDigester digester;
  
  public BasicPasswordEncryptor() {
    this.digester = new StandardStringDigester();
    this.digester.initialize();
  }
  
  public String encryptPassword(String password) {
    return this.digester.digest(password);
  }
  
  public boolean checkPassword(String plainPassword, String encryptedPassword) {
    return this.digester.matches(plainPassword, encryptedPassword);
  }
}
