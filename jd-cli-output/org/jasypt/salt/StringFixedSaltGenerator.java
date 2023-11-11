package org.jasypt.salt;

import java.io.UnsupportedEncodingException;
import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionInitializationException;

public class StringFixedSaltGenerator implements FixedSaltGenerator {
  private static final String DEFAULT_CHARSET = "UTF-8";
  
  private final String salt;
  
  private final String charset;
  
  private final byte[] saltBytes;
  
  public StringFixedSaltGenerator(String salt) {
    this(salt, null);
  }
  
  public StringFixedSaltGenerator(String salt, String charset) {
    CommonUtils.validateNotNull(salt, "Salt cannot be set null");
    this.salt = salt;
    this.charset = (charset != null) ? charset : "UTF-8";
    try {
      this.saltBytes = this.salt.getBytes(this.charset);
    } catch (UnsupportedEncodingException e) {
      throw new EncryptionInitializationException("Invalid charset specified: " + this.charset);
    } 
  }
  
  public byte[] generateSalt(int lengthBytes) {
    if (this.saltBytes.length < lengthBytes)
      throw new EncryptionInitializationException("Requested salt larger than set"); 
    byte[] generatedSalt = new byte[lengthBytes];
    System.arraycopy(this.saltBytes, 0, generatedSalt, 0, lengthBytes);
    return generatedSalt;
  }
  
  public boolean includePlainSaltInEncryptionResults() {
    return false;
  }
}
