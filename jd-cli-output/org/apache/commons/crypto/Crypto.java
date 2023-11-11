package org.apache.commons.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Properties;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;
import org.apache.commons.crypto.random.CryptoRandom;
import org.apache.commons.crypto.random.CryptoRandomFactory;

public final class Crypto {
  public static final String CONF_PREFIX = "commons.crypto.";
  
  public static final String LIB_NAME_KEY = "commons.crypto.lib.name";
  
  public static final String LIB_PATH_KEY = "commons.crypto.lib.path";
  
  public static final String LIB_TEMPDIR_KEY = "commons.crypto.lib.tempdir";
  
  private static class ComponentPropertiesHolder {
    static final Properties PROPERTIES = getComponentProperties();
    
    private static Properties getComponentProperties() {
      URL url = Crypto.class.getResource("/org/apache/commons/crypto/component.properties");
      Properties versionData = new Properties();
      if (url != null)
        try (InputStream inputStream = url.openStream()) {
          versionData.load(inputStream);
          return versionData;
        } catch (IOException iOException) {} 
      return versionData;
    }
  }
  
  public static String getComponentName() {
    return ComponentPropertiesHolder.PROPERTIES.getProperty("NAME");
  }
  
  public static String getComponentVersion() {
    return ComponentPropertiesHolder.PROPERTIES.getProperty("VERSION");
  }
  
  public static Throwable getLoadingError() {
    return NativeCodeLoader.getLoadingError();
  }
  
  private static void info(String format, Object... args) {
    System.out.println(String.format(format, args));
  }
  
  public static boolean isNativeCodeLoaded() {
    return NativeCodeLoader.isNativeCodeLoaded();
  }
  
  public static void main(String[] args) throws Exception {
    info("%s %s", new Object[] { getComponentName(), getComponentVersion() });
    if (isNativeCodeLoaded()) {
      info("Native code loaded OK: %s", new Object[] { OpenSslInfoNative.NativeVersion() });
      info("Native name: %s", new Object[] { OpenSslInfoNative.NativeName() });
      info("Native built: %s", new Object[] { OpenSslInfoNative.NativeTimeStamp() });
      info("OpenSSL library loaded OK, version: 0x%s", new Object[] { Long.toHexString(OpenSslInfoNative.OpenSSL()) });
      info("OpenSSL library info: %s", new Object[] { OpenSslInfoNative.OpenSSLVersion(0) });
      Properties props = new Properties();
      props.setProperty("commons.crypto.secure.random.classes", CryptoRandomFactory.RandomProvider.OPENSSL
          .getClassName());
      try (CryptoRandom cryptoRandom = CryptoRandomFactory.getCryptoRandom(props)) {
        info("Random instance created OK: %s", new Object[] { cryptoRandom });
      } 
      props = new Properties();
      props.setProperty("commons.crypto.cipher.classes", CryptoCipherFactory.CipherProvider.OPENSSL
          .getClassName());
      String transformation = "AES/CTR/NoPadding";
      try (CryptoCipher cryptoCipher = CryptoCipherFactory.getCryptoCipher("AES/CTR/NoPadding", props)) {
        info("Cipher %s instance created OK: %s", new Object[] { "AES/CTR/NoPadding", cryptoCipher });
      } 
      info("Additional OpenSSL_version(n) details:", new Object[0]);
      for (int j = 1; j < 6; j++) {
        info("%s: %s", new Object[] { Integer.valueOf(j), OpenSslInfoNative.OpenSSLVersion(j) });
      } 
    } else {
      info("Native load failed: %s", new Object[] { getLoadingError() });
    } 
  }
}
