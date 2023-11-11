package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.StagedAgreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

public class ECDHCStagedAgreement implements StagedAgreement {
  ECPrivateKeyParameters key;
  
  public void init(CipherParameters paramCipherParameters) {
    this.key = (ECPrivateKeyParameters)paramCipherParameters;
  }
  
  public int getFieldSize() {
    return (this.key.getParameters().getCurve().getFieldSize() + 7) / 8;
  }
  
  public AsymmetricKeyParameter calculateStage(CipherParameters paramCipherParameters) {
    ECPoint eCPoint = calculateNextPoint((ECPublicKeyParameters)paramCipherParameters);
    return new ECPublicKeyParameters(eCPoint, this.key.getParameters());
  }
  
  public BigInteger calculateAgreement(CipherParameters paramCipherParameters) {
    ECPoint eCPoint = calculateNextPoint((ECPublicKeyParameters)paramCipherParameters);
    return eCPoint.getAffineXCoord().toBigInteger();
  }
  
  private ECPoint calculateNextPoint(ECPublicKeyParameters paramECPublicKeyParameters) {
    ECPublicKeyParameters eCPublicKeyParameters = paramECPublicKeyParameters;
    ECDomainParameters eCDomainParameters = this.key.getParameters();
    if (!eCDomainParameters.equals(eCPublicKeyParameters.getParameters()))
      throw new IllegalStateException("ECDHC public key has wrong domain parameters"); 
    BigInteger bigInteger = eCDomainParameters.getH().multiply(this.key.getD()).mod(eCDomainParameters.getN());
    ECPoint eCPoint1 = ECAlgorithms.cleanPoint(eCDomainParameters.getCurve(), eCPublicKeyParameters.getQ());
    if (eCPoint1.isInfinity())
      throw new IllegalStateException("Infinity is not a valid public key for ECDHC"); 
    ECPoint eCPoint2 = eCPoint1.multiply(bigInteger).normalize();
    if (eCPoint2.isInfinity())
      throw new IllegalStateException("Infinity is not a valid agreement value for ECDHC"); 
    return eCPoint2;
  }
}
