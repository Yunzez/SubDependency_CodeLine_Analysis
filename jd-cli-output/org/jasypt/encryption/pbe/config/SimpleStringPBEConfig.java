package org.jasypt.encryption.pbe.config;

import org.jasypt.commons.CommonUtils;

public class SimpleStringPBEConfig extends SimplePBEConfig implements StringPBEConfig {
  private String stringOutputType = null;
  
  public void setStringOutputType(String stringOutputType) {
    this
      
      .stringOutputType = CommonUtils.getStandardStringOutputType(stringOutputType);
  }
  
  public String getStringOutputType() {
    return this.stringOutputType;
  }
}
