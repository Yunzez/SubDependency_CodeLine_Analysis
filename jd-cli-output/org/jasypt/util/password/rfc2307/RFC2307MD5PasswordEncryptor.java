package org.jasypt.util.password.rfc2307;

import org.jasypt.digest.StandardStringDigester;
import org.jasypt.util.password.PasswordEncryptor;

public final class RFC2307MD5PasswordEncryptor implements PasswordEncryptor {
  private final StandardStringDigester digester;
  
  public RFC2307MD5PasswordEncryptor() {
    this.digester = new StandardStringDigester();
    this.digester.setAlgorithm("MD5");
    this.digester.setIterations(1);
    this.digester.setSaltSizeBytes(0);
    this.digester.setPrefix("{MD5}");
  }
  
  public void setStringOutputType(String stringOutputType) {
    this.digester.setStringOutputType(stringOutputType);
  }
  
  public String encryptPassword(String password) {
    return this.digester.digest(password);
  }
  
  public boolean checkPassword(String plainPassword, String encryptedPassword) {
    return this.digester.matches(plainPassword, encryptedPassword);
  }
}
