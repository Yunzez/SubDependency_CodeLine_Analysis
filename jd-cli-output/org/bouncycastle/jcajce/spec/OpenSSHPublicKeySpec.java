package org.bouncycastle.jcajce.spec;

import java.security.spec.EncodedKeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class OpenSSHPublicKeySpec extends EncodedKeySpec {
  private static final String[] allowedTypes = new String[] { "ssh-rsa", "ssh-ed25519", "ssh-dss" };
  
  private final String type;
  
  public OpenSSHPublicKeySpec(byte[] paramArrayOfbyte) {
    super(paramArrayOfbyte);
    byte b1 = 0;
    int i = (paramArrayOfbyte[b1++] & 0xFF) << 24;
    i |= (paramArrayOfbyte[b1++] & 0xFF) << 16;
    i |= (paramArrayOfbyte[b1++] & 0xFF) << 8;
    i |= paramArrayOfbyte[b1++] & 0xFF;
    if (b1 + i >= paramArrayOfbyte.length)
      throw new IllegalArgumentException("invalid public key blob: type field longer than blob"); 
    this.type = Strings.fromByteArray(Arrays.copyOfRange(paramArrayOfbyte, b1, b1 + i));
    if (this.type.startsWith("ecdsa"))
      return; 
    for (byte b2 = 0; b2 < allowedTypes.length; b2++) {
      if (allowedTypes[b2].equals(this.type))
        return; 
    } 
    throw new IllegalArgumentException("unrecognised public key type " + this.type);
  }
  
  public String getFormat() {
    return "OpenSSH";
  }
  
  public String getType() {
    return this.type;
  }
}
