package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;

public class OpenSSHPrivateKeySpec extends EncodedKeySpec {
  private final String format;
  
  public OpenSSHPrivateKeySpec(byte[] paramArrayOfbyte) {
    super(paramArrayOfbyte);
    if (paramArrayOfbyte[0] == 48) {
      this.format = "ASN.1";
    } else if (paramArrayOfbyte[0] == 111) {
      this.format = "OpenSSH";
    } else {
      throw new IllegalArgumentException("unknown byte encoding");
    } 
  }
  
  public String getFormat() {
    return this.format;
  }
}
