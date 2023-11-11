package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;

public final class X25519Agreement implements RawAgreement {
  private X25519PrivateKeyParameters privateKey;
  
  public void init(CipherParameters paramCipherParameters) {
    this.privateKey = (X25519PrivateKeyParameters)paramCipherParameters;
  }
  
  public int getAgreementSize() {
    return 32;
  }
  
  public void calculateAgreement(CipherParameters paramCipherParameters, byte[] paramArrayOfbyte, int paramInt) {
    this.privateKey.generateSecret((X25519PublicKeyParameters)paramCipherParameters, paramArrayOfbyte, paramInt);
  }
}
