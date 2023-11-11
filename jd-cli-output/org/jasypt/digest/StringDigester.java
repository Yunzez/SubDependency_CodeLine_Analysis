package org.jasypt.digest;

public interface StringDigester {
  String digest(String paramString);
  
  boolean matches(String paramString1, String paramString2);
}
