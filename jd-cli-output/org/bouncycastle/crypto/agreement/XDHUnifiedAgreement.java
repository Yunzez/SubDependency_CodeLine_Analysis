package org.bouncycastle.crypto.agreement;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.XDHUPrivateParameters;
import org.bouncycastle.crypto.params.XDHUPublicParameters;

public class XDHUnifiedAgreement implements RawAgreement {
  private final RawAgreement xAgreement;
  
  private XDHUPrivateParameters privParams;
  
  public XDHUnifiedAgreement(RawAgreement paramRawAgreement) {
    this.xAgreement = paramRawAgreement;
  }
  
  public void init(CipherParameters paramCipherParameters) {
    this.privParams = (XDHUPrivateParameters)paramCipherParameters;
  }
  
  public int getAgreementSize() {
    return this.xAgreement.getAgreementSize() * 2;
  }
  
  public void calculateAgreement(CipherParameters paramCipherParameters, byte[] paramArrayOfbyte, int paramInt) {
    XDHUPublicParameters xDHUPublicParameters = (XDHUPublicParameters)paramCipherParameters;
    this.xAgreement.init(this.privParams.getEphemeralPrivateKey());
    this.xAgreement.calculateAgreement(xDHUPublicParameters.getEphemeralPublicKey(), paramArrayOfbyte, paramInt);
    this.xAgreement.init(this.privParams.getStaticPrivateKey());
    this.xAgreement.calculateAgreement(xDHUPublicParameters.getStaticPublicKey(), paramArrayOfbyte, paramInt + this.xAgreement.getAgreementSize());
  }
}
