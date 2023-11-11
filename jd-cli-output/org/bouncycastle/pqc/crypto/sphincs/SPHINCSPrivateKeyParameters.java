package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.util.Arrays;

public class SPHINCSPrivateKeyParameters extends SPHINCSKeyParameters {
  private final byte[] keyData;
  
  public SPHINCSPrivateKeyParameters(byte[] paramArrayOfbyte) {
    super(true, null);
    this.keyData = Arrays.clone(paramArrayOfbyte);
  }
  
  public SPHINCSPrivateKeyParameters(byte[] paramArrayOfbyte, String paramString) {
    super(true, paramString);
    this.keyData = Arrays.clone(paramArrayOfbyte);
  }
  
  public byte[] getKeyData() {
    return Arrays.clone(this.keyData);
  }
}
