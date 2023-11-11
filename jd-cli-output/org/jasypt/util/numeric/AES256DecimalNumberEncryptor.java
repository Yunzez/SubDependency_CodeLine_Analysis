package org.jasypt.util.numeric;

import java.math.BigDecimal;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.iv.RandomIvGenerator;

public final class AES256DecimalNumberEncryptor implements DecimalNumberEncryptor {
  private final StandardPBEBigDecimalEncryptor encryptor;
  
  public AES256DecimalNumberEncryptor() {
    this.encryptor = new StandardPBEBigDecimalEncryptor();
    this.encryptor.setAlgorithm("PBEWithHMACSHA512AndAES_256");
    this.encryptor.setIvGenerator(new RandomIvGenerator());
  }
  
  public void setPassword(String password) {
    this.encryptor.setPassword(password);
  }
  
  public void setPasswordCharArray(char[] password) {
    this.encryptor.setPasswordCharArray(password);
  }
  
  public BigDecimal encrypt(BigDecimal number) {
    return this.encryptor.encrypt(number);
  }
  
  public BigDecimal decrypt(BigDecimal encryptedNumber) {
    return this.encryptor.decrypt(encryptedNumber);
  }
}
