package org.jasypt.util.numeric;

import java.math.BigInteger;

public interface IntegerNumberEncryptor {
  BigInteger encrypt(BigInteger paramBigInteger);
  
  BigInteger decrypt(BigInteger paramBigInteger);
}
