package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DHUPrivateParameters;
import org.bouncycastle.crypto.params.DHUPublicParameters;
import org.bouncycastle.util.BigIntegers;

public class DHUnifiedAgreement {
  private DHUPrivateParameters privParams;
  
  public void init(CipherParameters paramCipherParameters) {
    this.privParams = (DHUPrivateParameters)paramCipherParameters;
  }
  
  public int getFieldSize() {
    return (this.privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
  }
  
  public byte[] calculateAgreement(CipherParameters paramCipherParameters) {
    DHUPublicParameters dHUPublicParameters = (DHUPublicParameters)paramCipherParameters;
    DHBasicAgreement dHBasicAgreement1 = new DHBasicAgreement();
    DHBasicAgreement dHBasicAgreement2 = new DHBasicAgreement();
    dHBasicAgreement1.init(this.privParams.getStaticPrivateKey());
    BigInteger bigInteger1 = dHBasicAgreement1.calculateAgreement(dHUPublicParameters.getStaticPublicKey());
    dHBasicAgreement2.init(this.privParams.getEphemeralPrivateKey());
    BigInteger bigInteger2 = dHBasicAgreement2.calculateAgreement(dHUPublicParameters.getEphemeralPublicKey());
    int i = getFieldSize();
    byte[] arrayOfByte = new byte[i * 2];
    BigIntegers.asUnsignedByteArray(bigInteger2, arrayOfByte, 0, i);
    BigIntegers.asUnsignedByteArray(bigInteger1, arrayOfByte, i, i);
    return arrayOfByte;
  }
}
