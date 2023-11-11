package org.jasypt.util.numeric;

import java.math.BigDecimal;

public interface DecimalNumberEncryptor {
  BigDecimal encrypt(BigDecimal paramBigDecimal);
  
  BigDecimal decrypt(BigDecimal paramBigDecimal);
}
