package org.jasypt.properties;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Properties;
import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.StringEncryptor;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.util.text.TextEncryptor;

public final class EncryptableProperties extends Properties {
  private static final long serialVersionUID = 6479795856725500639L;
  
  private final Integer ident = new Integer(CommonUtils.nextRandomInt());
  
  private transient StringEncryptor stringEncryptor = null;
  
  private transient TextEncryptor textEncryptor = null;
  
  public EncryptableProperties(StringEncryptor stringEncryptor) {
    this((Properties)null, stringEncryptor);
  }
  
  public EncryptableProperties(TextEncryptor textEncryptor) {
    this((Properties)null, textEncryptor);
  }
  
  public EncryptableProperties(Properties defaults, StringEncryptor stringEncryptor) {
    super(defaults);
    CommonUtils.validateNotNull(stringEncryptor, "Encryptor cannot be null");
    this.stringEncryptor = stringEncryptor;
    this.textEncryptor = null;
  }
  
  public EncryptableProperties(Properties defaults, TextEncryptor textEncryptor) {
    super(defaults);
    CommonUtils.validateNotNull(textEncryptor, "Encryptor cannot be null");
    this.stringEncryptor = null;
    this.textEncryptor = textEncryptor;
  }
  
  public String getProperty(String key) {
    return decode(super.getProperty(key));
  }
  
  public String getProperty(String key, String defaultValue) {
    return decode(super.getProperty(key, defaultValue));
  }
  
  public synchronized Object get(Object key) {
    Object value = super.get(key);
    String valueStr = (value instanceof String) ? (String)value : null;
    return decode(valueStr);
  }
  
  Integer getIdent() {
    return this.ident;
  }
  
  private synchronized String decode(String encodedValue) {
    if (!PropertyValueEncryptionUtils.isEncryptedValue(encodedValue))
      return encodedValue; 
    if (this.stringEncryptor != null)
      return PropertyValueEncryptionUtils.decrypt(encodedValue, this.stringEncryptor); 
    if (this.textEncryptor != null)
      return PropertyValueEncryptionUtils.decrypt(encodedValue, this.textEncryptor); 
    throw new EncryptionOperationNotPossibleException("Neither a string encryptor nor a text encryptor exist for this instance of EncryptableProperties. This is usually caused by the instance having been serialized and then de-serialized in a different classloader or virtual machine, which is an unsupported behaviour (as encryptors cannot be serialized themselves)");
  }
  
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    EncryptablePropertiesEncryptorRegistry registry = EncryptablePropertiesEncryptorRegistry.getInstance();
    StringEncryptor registeredStringEncryptor = registry.getStringEncryptor(this);
    if (registeredStringEncryptor != null) {
      this.stringEncryptor = registeredStringEncryptor;
      return;
    } 
    TextEncryptor registeredTextEncryptor = registry.getTextEncryptor(this);
    if (registeredTextEncryptor != null)
      this.textEncryptor = registeredTextEncryptor; 
  }
  
  private void writeObject(ObjectOutputStream outputStream) throws IOException {
    EncryptablePropertiesEncryptorRegistry registry = EncryptablePropertiesEncryptorRegistry.getInstance();
    if (this.textEncryptor != null) {
      registry.setTextEncryptor(this, this.textEncryptor);
    } else if (this.stringEncryptor != null) {
      registry.setStringEncryptor(this, this.stringEncryptor);
    } 
    outputStream.defaultWriteObject();
  }
}
