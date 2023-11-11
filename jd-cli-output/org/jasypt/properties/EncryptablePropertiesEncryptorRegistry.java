package org.jasypt.properties;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.util.text.TextEncryptor;

final class EncryptablePropertiesEncryptorRegistry {
  private static final EncryptablePropertiesEncryptorRegistry instance = new EncryptablePropertiesEncryptorRegistry();
  
  private final Map stringEncryptors = Collections.synchronizedMap(new HashMap<Object, Object>());
  
  private final Map textEncryptors = Collections.synchronizedMap(new HashMap<Object, Object>());
  
  static EncryptablePropertiesEncryptorRegistry getInstance() {
    return instance;
  }
  
  void removeEntries(EncryptableProperties prop) {
    this.stringEncryptors.remove(prop.getIdent());
    this.textEncryptors.remove(prop.getIdent());
  }
  
  StringEncryptor getStringEncryptor(EncryptableProperties prop) {
    return (StringEncryptor)this.stringEncryptors.get(prop.getIdent());
  }
  
  void setStringEncryptor(EncryptableProperties prop, StringEncryptor encryptor) {
    this.stringEncryptors.put(prop.getIdent(), encryptor);
  }
  
  TextEncryptor getTextEncryptor(EncryptableProperties prop) {
    return (TextEncryptor)this.textEncryptors.get(prop.getIdent());
  }
  
  void setTextEncryptor(EncryptableProperties prop, TextEncryptor encryptor) {
    this.textEncryptors.put(prop.getIdent(), encryptor);
  }
}
