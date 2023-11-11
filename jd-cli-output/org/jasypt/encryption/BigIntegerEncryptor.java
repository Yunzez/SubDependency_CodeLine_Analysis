package org.jasypt.encryption;

import java.math.BigInteger;

public interface BigIntegerEncryptor {
  BigInteger encrypt(BigInteger paramBigInteger);
  
  BigInteger decrypt(BigInteger paramBigInteger);
}
