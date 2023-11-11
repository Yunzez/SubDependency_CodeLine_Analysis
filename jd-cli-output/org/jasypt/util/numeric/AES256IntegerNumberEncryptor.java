package org.jasypt.util.numeric;

import java.math.BigInteger;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.iv.RandomIvGenerator;

public final class AES256IntegerNumberEncryptor implements IntegerNumberEncryptor {
  private final StandardPBEBigIntegerEncryptor encryptor;
  
  public AES256IntegerNumberEncryptor() {
    this.encryptor = new StandardPBEBigIntegerEncryptor();
    this.encryptor.setAlgorithm("PBEWithHMACSHA512AndAES_256");
    this.encryptor.setIvGenerator(new RandomIvGenerator());
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
