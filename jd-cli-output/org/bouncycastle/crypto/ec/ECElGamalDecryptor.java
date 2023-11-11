package org.bouncycastle.crypto.ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ECElGamalDecryptor implements ECDecryptor {
  private ECPrivateKeyParameters key;
  
  public void init(CipherParameters paramCipherParameters) {
    if (!(paramCipherParameters instanceof ECPrivateKeyParameters))
      throw new IllegalArgumentException("ECPrivateKeyParameters are required for decryption."); 
    this.key = (ECPrivateKeyParameters)paramCipherParameters;
  }
  
  public ECPoint decrypt(ECPair paramECPair) {
    if (this.key == null)
      throw new IllegalStateException("ECElGamalDecryptor not initialised"); 
    ECCurve eCCurve = this.key.getParameters().getCurve();
    ECPoint eCPoint = ECAlgorithms.cleanPoint(eCCurve, paramECPair.getX()).multiply(this.key.getD());
    return ECAlgorithms.cleanPoint(eCCurve, paramECPair.getY()).subtract(eCPoint).normalize();
  }
}
