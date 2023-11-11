package org.jasypt.util.password;

import org.jasypt.digest.StandardStringDigester;

public final class StrongPasswordEncryptor implements PasswordEncryptor {
  private final StandardStringDigester digester;
  
  public StrongPasswordEncryptor() {
    this.digester = new StandardStringDigester();
    this.digester.setAlgorithm("SHA-256");
    this.digester.setIterations(100000);
    this.digester.setSaltSizeBytes(16);
    this.digester.initialize();
  }
  
  public String encryptPassword(String password) {
    return this.digester.digest(password);
  }
  
  public boolean checkPassword(String plainPassword, String encryptedPassword) {
    return this.digester.matches(plainPassword, encryptedPassword);
  }
}
