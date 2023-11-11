package org.jasypt.util.numeric;

import java.math.BigDecimal;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;

public final class StrongDecimalNumberEncryptor implements DecimalNumberEncryptor {
  private final StandardPBEBigDecimalEncryptor encryptor;
  
  public StrongDecimalNumberEncryptor() {
    this.encryptor = new StandardPBEBigDecimalEncryptor();
    this.encryptor.setAlgorithm("PBEWithMD5AndTripleDES");
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
