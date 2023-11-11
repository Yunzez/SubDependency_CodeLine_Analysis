package org.jasypt.util.numeric;

import java.math.BigInteger;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;

public final class StrongIntegerNumberEncryptor implements IntegerNumberEncryptor {
  private final StandardPBEBigIntegerEncryptor encryptor;
  
  public StrongIntegerNumberEncryptor() {
    this.encryptor = new StandardPBEBigIntegerEncryptor();
    this.encryptor.setAlgorithm("PBEWithMD5AndTripleDES");
  }
  
  public void setPassword(String password) {
    this.encryptor.setPassword(password);
  }
  
  public void setPasswordCharArray(char[] password) {
    this.encryptor.setPasswordCharArray(password);
  }
  
  public BigInteger encrypt(BigInteger number) {
    return this.encryptor.encrypt(number);
  }
  
  public BigInteger decrypt(BigInteger encryptedNumber) {
    return this.encryptor.decrypt(encryptedNumber);
  }
}
