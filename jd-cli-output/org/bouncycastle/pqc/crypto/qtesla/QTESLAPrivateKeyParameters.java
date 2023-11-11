package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

public final class QTESLAPrivateKeyParameters extends AsymmetricKeyParameter {
  private int securityCategory;
  
  private byte[] privateKey;
  
  public QTESLAPrivateKeyParameters(int paramInt, byte[] paramArrayOfbyte) {
    super(true);
    if (paramArrayOfbyte.length != QTESLASecurityCategory.getPrivateSize(paramInt))
      throw new IllegalArgumentException("invalid key size for security category"); 
    this.securityCategory = paramInt;
    this.privateKey = Arrays.clone(paramArrayOfbyte);
  }
  
  public int getSecurityCategory() {
    return this.securityCategory;
  }
  
  public byte[] getSecret() {
    return Arrays.clone(this.privateKey);
  }
}
