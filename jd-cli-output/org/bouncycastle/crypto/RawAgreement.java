package org.bouncycastle.crypto;

public interface RawAgreement {
  void init(CipherParameters paramCipherParameters);
  
  int getAgreementSize();
  
  void calculateAgreement(CipherParameters paramCipherParameters, byte[] paramArrayOfbyte, int paramInt);
}
