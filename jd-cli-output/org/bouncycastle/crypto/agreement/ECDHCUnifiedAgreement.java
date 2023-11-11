package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDHUPrivateParameters;
import org.bouncycastle.crypto.params.ECDHUPublicParameters;
import org.bouncycastle.util.BigIntegers;

public class ECDHCUnifiedAgreement {
  private ECDHUPrivateParameters privParams;
  
  public void init(CipherParameters paramCipherParameters) {
    this.privParams = (ECDHUPrivateParameters)paramCipherParameters;
  }
  
  public int getFieldSize() {
    return (this.privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
  }
  
  public byte[] calculateAgreement(CipherParameters paramCipherParameters) {
    ECDHUPublicParameters eCDHUPublicParameters = (ECDHUPublicParameters)paramCipherParameters;
    ECDHCBasicAgreement eCDHCBasicAgreement1 = new ECDHCBasicAgreement();
    ECDHCBasicAgreement eCDHCBasicAgreement2 = new ECDHCBasicAgreement();
    eCDHCBasicAgreement1.init(this.privParams.getStaticPrivateKey());
    BigInteger bigInteger1 = eCDHCBasicAgreement1.calculateAgreement(eCDHUPublicParameters.getStaticPublicKey());
    eCDHCBasicAgreement2.init(this.privParams.getEphemeralPrivateKey());
    BigInteger bigInteger2 = eCDHCBasicAgreement2.calculateAgreement(eCDHUPublicParameters.getEphemeralPublicKey());
    int i = getFieldSize();
    byte[] arrayOfByte = new byte[i * 2];
    BigIntegers.asUnsignedByteArray(bigInteger2, arrayOfByte, 0, i);
    BigIntegers.asUnsignedByteArray(bigInteger1, arrayOfByte, i, i);
    return arrayOfByte;
  }
}
