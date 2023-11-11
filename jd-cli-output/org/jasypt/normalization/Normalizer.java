package org.jasypt.normalization;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import org.jasypt.exceptions.EncryptionInitializationException;

public final class Normalizer {
  private static final String ICU_NORMALIZER_CLASS_NAME = "com.ibm.icu.text.Normalizer";
  
  private static final String JDK_NORMALIZER_CLASS_NAME = "java.text.Normalizer";
  
  private static final String JDK_NORMALIZER_FORM_CLASS_NAME = "java.text.Normalizer$Form";
  
  private static Boolean useIcuNormalizer = null;
  
  private static Method javaTextNormalizerMethod = null;
  
  private static Object javaTextNormalizerFormNFCConstant = null;
  
  public static String normalizeToNfc(String message) {
    return new String(normalizeToNfc(message.toCharArray()));
  }
  
  public static char[] normalizeToNfc(char[] message) {
    if (useIcuNormalizer == null)
      try {
        initializeIcu4j();
      } catch (ClassNotFoundException e) {
        try {
          initializeJavaTextNormalizer();
        } catch (ClassNotFoundException e2) {
          throw new EncryptionInitializationException("Cannot find a valid UNICODE normalizer: neither java.text.Normalizer nor com.ibm.icu.text.Normalizer have been found at the classpath. If you are using a version of the JDK older than JavaSE 6, you should include the icu4j library in your classpath.");
        } catch (NoSuchMethodException e2) {
          throw new EncryptionInitializationException("Cannot find a valid UNICODE normalizer: java.text.Normalizer has been found at the classpath, but has an incompatible signature for its 'normalize' method.");
        } catch (NoSuchFieldException e2) {
          throw new EncryptionInitializationException("Cannot find a valid UNICODE normalizer: java.text.Normalizer$Form has been found at the classpath, but seems to have no 'NFC' value.");
        } catch (IllegalAccessException e2) {
          throw new EncryptionInitializationException("Cannot find a valid UNICODE normalizer: java.text.Normalizer$Form has been found at the classpath, but seems to have no 'NFC' value.");
        } 
      }  
    if (useIcuNormalizer.booleanValue())
      return normalizeWithIcu4j(message); 
    return normalizeWithJavaNormalizer(message);
  }
  
  static void initializeIcu4j() throws ClassNotFoundException {
    Thread.currentThread().getContextClassLoader().loadClass("com.ibm.icu.text.Normalizer");
    useIcuNormalizer = Boolean.TRUE;
  }
  
  static void initializeJavaTextNormalizer() throws ClassNotFoundException, NoSuchMethodException, NoSuchFieldException, IllegalAccessException {
    Class<?> javaTextNormalizerClass = Thread.currentThread().getContextClassLoader().loadClass("java.text.Normalizer");
    Class<?> javaTextNormalizerFormClass = Thread.currentThread().getContextClassLoader().loadClass("java.text.Normalizer$Form");
    javaTextNormalizerMethod = javaTextNormalizerClass.getMethod("normalize", new Class[] { CharSequence.class, javaTextNormalizerFormClass });
    Field javaTextNormalizerFormNFCConstantField = javaTextNormalizerFormClass.getField("NFC");
    javaTextNormalizerFormNFCConstant = javaTextNormalizerFormNFCConstantField.get(null);
    useIcuNormalizer = Boolean.FALSE;
  }
  
  static char[] normalizeWithJavaNormalizer(char[] message) {
    String result;
    if (javaTextNormalizerMethod == null || javaTextNormalizerFormNFCConstant == null)
      throw new EncryptionInitializationException("Cannot use: java.text.Normalizer$Form, as JDK-based normalization has not been initialized! (check previous execution errors)"); 
    String messageStr = new String(message);
    try {
      result = (String)javaTextNormalizerMethod.invoke(null, new Object[] { messageStr, javaTextNormalizerFormNFCConstant });
    } catch (Exception e) {
      throw new EncryptionInitializationException("Could not perform a valid UNICODE normalization", e);
    } 
    return result.toCharArray();
  }
  
  static char[] normalizeWithIcu4j(char[] message) {
    char[] normalizationResult = new char[message.length * 2];
    int normalizationResultSize = 0;
    while (true) {
      normalizationResultSize = com.ibm.icu.text.Normalizer.normalize(message, normalizationResult, com.ibm.icu.text.Normalizer.NFC, 0);
      if (normalizationResultSize <= normalizationResult.length) {
        char[] result = new char[normalizationResultSize];
        System.arraycopy(normalizationResult, 0, result, 0, normalizationResultSize);
        for (int j = 0; j < normalizationResult.length; j++)
          normalizationResult[j] = Character.MIN_VALUE; 
        return result;
      } 
      for (int i = 0; i < normalizationResult.length; i++)
        normalizationResult[i] = Character.MIN_VALUE; 
      normalizationResult = new char[normalizationResultSize];
    } 
  }
}
