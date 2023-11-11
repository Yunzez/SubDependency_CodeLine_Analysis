package org.apache.commons.crypto.utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.CryptoCipherFactory;

public final class Utils {
  private static final String SYSTEM_PROPERTIES_FILE = "commons.crypto.properties";
  
  private static class DefaultPropertiesHolder {
    static final Properties DEFAULT_PROPERTIES = Utils.createDefaultProperties();
  }
  
  private static Properties createDefaultProperties() {
    Properties defaultedProps = new Properties(System.getProperties());
    try {
      Properties fileProps = new Properties();
      try (InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream("commons.crypto.properties")) {
        if (is == null)
          return defaultedProps; 
        fileProps.load(is);
      } 
      Enumeration<?> names = fileProps.propertyNames();
      while (names.hasMoreElements()) {
        String name = (String)names.nextElement();
        if (System.getProperty(name) == null)
          defaultedProps.setProperty(name, fileProps.getProperty(name)); 
      } 
    } catch (Exception ex) {
      System.err.println("Could not load 'commons.crypto.properties' from classpath: " + ex
          
          .toString());
    } 
    return defaultedProps;
  }
  
  public static Properties getDefaultProperties() {
    return new Properties(DefaultPropertiesHolder.DEFAULT_PROPERTIES);
  }
  
  public static Properties getProperties(Properties newProp) {
    Properties properties = new Properties(DefaultPropertiesHolder.DEFAULT_PROPERTIES);
    properties.putAll(newProp);
    return properties;
  }
  
  public static CryptoCipher getCipherInstance(String transformation, Properties properties) throws IOException {
    try {
      return CryptoCipherFactory.getCryptoCipher(transformation, properties);
    } catch (GeneralSecurityException e) {
      throw new IOException(e);
    } 
  }
  
  public static void checkArgument(boolean expression) {
    if (!expression)
      throw new IllegalArgumentException(); 
  }
  
  public static void checkArgument(boolean expression, Object errorMessage) {
    if (!expression)
      throw new IllegalArgumentException(String.valueOf(errorMessage)); 
  }
  
  @Deprecated
  public static <T> T checkNotNull(T reference) {
    return Objects.requireNonNull(reference, "reference");
  }
  
  public static void checkState(boolean expression) {
    checkState(expression, null);
  }
  
  public static void checkState(boolean expression, String message) {
    if (!expression)
      throw new IllegalStateException(message); 
  }
  
  public static List<String> splitClassNames(String clazzNames, String separator) {
    List<String> res = new ArrayList<>();
    if (clazzNames == null || clazzNames.isEmpty())
      return res; 
    for (String clazzName : clazzNames.split(separator)) {
      clazzName = clazzName.trim();
      if (!clazzName.isEmpty())
        res.add(clazzName); 
    } 
    return res;
  }
}
