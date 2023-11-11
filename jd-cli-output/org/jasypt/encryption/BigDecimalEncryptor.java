package org.jasypt.encryption;

import java.math.BigDecimal;

public interface BigDecimalEncryptor {
  BigDecimal encrypt(BigDecimal paramBigDecimal);
  
  BigDecimal decrypt(BigDecimal paramBigDecimal);
}
