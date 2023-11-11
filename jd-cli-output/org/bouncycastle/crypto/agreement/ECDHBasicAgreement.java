package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;

public class ECDHBasicAgreement implements BasicAgreement {
  private ECPrivateKeyParameters key;
  
  public void init(CipherParameters paramCipherParameters) {
    this.key = (ECPrivateKeyParameters)paramCipherParameters;
  }
  
  public int getFieldSize() {
    return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
  }
  
  public BigInteger calculateAgreement(CipherParameters paramCipherParameters) {
    ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters)paramCipherParameters;
    ECDomainParameters eCDomainParameters = this.key.getParameters();
    if (!eCDomainParameters.equals(eCPublicKeyParameters.getParameters()))
      throw new IllegalStateException("ECDH public key has wrong domain parameters"); 
    BigInteger bigInteger1 = this.key.getD();
    ECPoint eCPoint1 = ECAlgorithms.cleanPoint(eCDomainParameters.getCurve(), eCPublicKeyParameters.getQ());
    if (eCPoint1.isInfinity())
      throw new IllegalStateException("Infinity is not a valid public key for ECDH"); 
    BigInteger bigInteger2 = eCDomainParameters.getH();
    if (!bigInteger2.equals(ECConstants.ONE)) {
      bigInteger1 = eCDomainParameters.getHInv().multiply(bigInteger1).mod(eCDomainParameters.getN());
      eCPoint1 = ECAlgorithms.referenceMultiply(eCPoint1, bigInteger2);
    } 
    ECPoint eCPoint2 = eCPoint1.multiply(bigInteger1).normalize();
    if (eCPoint2.isInfinity())
      throw new IllegalStateException("Infinity is not a valid agreement value for ECDH"); 
    return eCPoint2.getAffineXCoord().toBigInteger();
  }
}
