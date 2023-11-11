package org.jasypt.digest.config;

public interface StringDigesterConfig extends DigesterConfig {
  Boolean isUnicodeNormalizationIgnored();
  
  String getStringOutputType();
  
  String getPrefix();
  
  String getSuffix();
}
