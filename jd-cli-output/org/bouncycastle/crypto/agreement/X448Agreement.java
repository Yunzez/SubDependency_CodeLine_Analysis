package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;

public final class X448Agreement implements RawAgreement {
  private X448PrivateKeyParameters privateKey;
  
  public void init(CipherParameters paramCipherParameters) {
    this.privateKey = (X448PrivateKeyParameters)paramCipherParameters;
  }
  
  public int getAgreementSize() {
    return 56;
  }
  
  public void calculateAgreement(CipherParameters paramCipherParameters, byte[] paramArrayOfbyte, int paramInt) {
    this.privateKey.generateSecret((X448PublicKeyParameters)paramCipherParameters, paramArrayOfbyte, paramInt);
  }
}
