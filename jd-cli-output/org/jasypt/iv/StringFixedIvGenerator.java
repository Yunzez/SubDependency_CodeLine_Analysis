package org.jasypt.iv;

import java.io.UnsupportedEncodingException;
import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionInitializationException;

public class StringFixedIvGenerator implements FixedIvGenerator {
  private static final String DEFAULT_CHARSET = "UTF-8";
  
  private final String iv;
  
  private final String charset;
  
  private final byte[] ivBytes;
  
  public StringFixedIvGenerator(String iv) {
    this(iv, null);
  }
  
  public StringFixedIvGenerator(String iv, String charset) {
    CommonUtils.validateNotNull(iv, "IV cannot be set null");
    this.iv = iv;
    this.charset = (charset != null) ? charset : "UTF-8";
    try {
      this.ivBytes = this.iv.getBytes(this.charset);
    } catch (UnsupportedEncodingException e) {
      throw new EncryptionInitializationException("Invalid charset specified: " + this.charset);
    } 
  }
  
  public byte[] generateIv(int lengthBytes) {
    if (this.ivBytes.length < lengthBytes)
      throw new EncryptionInitializationException("Requested IV larger than set"); 
    byte[] generatedIv = new byte[lengthBytes];
    System.arraycopy(this.ivBytes, 0, generatedIv, 0, lengthBytes);
    return generatedIv;
  }
  
  public boolean includePlainIvInEncryptionResults() {
    return false;
  }
}
