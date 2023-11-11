package org.apache.commons.crypto.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Properties;
import java.util.Random;

class JavaCryptoRandom extends Random implements CryptoRandom {
  private static final long serialVersionUID = 5517475898166660050L;
  
  private SecureRandom instance;
  
  public JavaCryptoRandom(Properties properties) {
    try {
      this
        .instance = SecureRandom.getInstance(properties
          .getProperty("commons.crypto.secure.random.java.algorithm", "SHA1PRNG"));
    } catch (NoSuchAlgorithmException e) {
      this.instance = new SecureRandom();
    } 
  }
  
  public void close() {}
  
  public void nextBytes(byte[] bytes) {
    this.instance.nextBytes(bytes);
  }
}
