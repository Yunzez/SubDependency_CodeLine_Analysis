package org.apache.commons.crypto.random;

import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Properties;
import org.apache.commons.crypto.utils.ReflectionUtils;
import org.apache.commons.crypto.utils.Utils;

public class CryptoRandomFactory {
  public static final String DEVICE_FILE_PATH_KEY = "commons.crypto.secure.random.device.file.path";
  
  public static final String DEVICE_FILE_PATH_DEFAULT = "/dev/urandom";
  
  public static final String JAVA_ALGORITHM_KEY = "commons.crypto.secure.random.java.algorithm";
  
  public static final String JAVA_ALGORITHM_DEFAULT = "SHA1PRNG";
  
  public static final String CLASSES_KEY = "commons.crypto.secure.random.classes";
  
  public enum RandomProvider {
    OPENSSL((String)OpenSslCryptoRandom.class),
    JAVA((String)JavaCryptoRandom.class),
    OS((String)OsCryptoRandom.class);
    
    private final Class<? extends CryptoRandom> klass;
    
    private final String className;
    
    RandomProvider(Class<? extends CryptoRandom> klass) {
      this.klass = klass;
      this.className = klass.getName();
    }
    
    public String getClassName() {
      return this.className;
    }
    
    public Class<? extends CryptoRandom> getImplClass() {
      return this.klass;
    }
  }
  
  private static final String CLASSES_DEFAULT = RandomProvider.OPENSSL
    .getClassName()
    .concat(",")
    .concat(RandomProvider.JAVA.getClassName());
  
  public static CryptoRandom getCryptoRandom() throws GeneralSecurityException {
    Properties properties = new Properties();
    return getCryptoRandom(properties);
  }
  
  public static CryptoRandom getCryptoRandom(Properties props) throws GeneralSecurityException {
    List<String> names = Utils.splitClassNames(getRandomClassString(props), ",");
    if (names.size() == 0)
      throw new IllegalArgumentException("No class name(s) provided"); 
    StringBuilder errorMessage = new StringBuilder();
    CryptoRandom random = null;
    Exception lastException = null;
    for (String klassName : names) {
      try {
        Class<?> klass = ReflectionUtils.getClassByName(klassName);
        random = (CryptoRandom)ReflectionUtils.newInstance(klass, new Object[] { props });
        if (random != null)
          break; 
      } catch (ClassCastException e) {
        lastException = e;
        errorMessage.append("Class: [" + klassName + "] is not a CryptoRandom.");
      } catch (ClassNotFoundException e) {
        lastException = e;
        errorMessage.append("CryptoRandom: [" + klassName + "] not found.");
      } catch (Exception e) {
        lastException = e;
        errorMessage.append("CryptoRandom: [" + klassName + "] failed with " + e.getMessage());
      } 
    } 
    if (random != null)
      return random; 
    throw new GeneralSecurityException(errorMessage.toString(), lastException);
  }
  
  private static String getRandomClassString(Properties props) {
    String randomClassString = props.getProperty("commons.crypto.secure.random.classes", CLASSES_DEFAULT);
    if (randomClassString.isEmpty())
      randomClassString = CLASSES_DEFAULT; 
    return randomClassString;
  }
}
