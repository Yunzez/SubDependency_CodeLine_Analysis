package org.apache.commons.crypto.jna;

import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.random.CryptoRandom;

public final class OpenSslJna {
  static void debug(String format, Object... args) {
    if (Boolean.getBoolean("commons.crypto.debug"))
      System.out.println(String.format(format, args)); 
  }
  
  public static Class<? extends CryptoCipher> getCipherClass() {
    return (Class)OpenSslJnaCipher.class;
  }
  
  public static Class<? extends CryptoRandom> getRandomClass() {
    return (Class)OpenSslJnaCryptoRandom.class;
  }
  
  private static void info(String format, Object... args) {
    System.out.println(String.format(format, args));
  }
  
  public static Throwable initialisationError() {
    return OpenSslNativeJna.INIT_ERROR;
  }
  
  public static boolean isEnabled() {
    return OpenSslNativeJna.INIT_OK;
  }
  
  public static void main(String[] args) {
    info("isEnabled(): %s", new Object[] { Boolean.valueOf(isEnabled()) });
    Throwable initialisationError = initialisationError();
    info("initialisationError(): %s", new Object[] { initialisationError });
    if (initialisationError != null) {
      System.err.flush();
      initialisationError.printStackTrace();
    } 
  }
  
  static String OpenSSLVersion(int type) {
    return OpenSslNativeJna.OpenSSLVersion(type);
  }
}
