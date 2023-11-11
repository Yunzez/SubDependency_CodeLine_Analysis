package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

public class MQVBasicAgreement implements BasicAgreement {
  private static final BigInteger ONE = BigInteger.valueOf(1L);
  
  DHMQVPrivateParameters privParams;
  
  public void init(CipherParameters paramCipherParameters) {
    this.privParams = (DHMQVPrivateParameters)paramCipherParameters;
  }
  
  public int getFieldSize() {
    return (this.privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
  }
  
  public BigInteger calculateAgreement(CipherParameters paramCipherParameters) {
    DHMQVPublicParameters dHMQVPublicParameters = (DHMQVPublicParameters)paramCipherParameters;
    DHPrivateKeyParameters dHPrivateKeyParameters = this.privParams.getStaticPrivateKey();
    if (!this.privParams.getStaticPrivateKey().getParameters().equals(dHMQVPublicParameters.getStaticPublicKey().getParameters()))
      throw new IllegalStateException("MQV public key components have wrong domain parameters"); 
    if (this.privParams.getStaticPrivateKey().getParameters().getQ() == null)
      throw new IllegalStateException("MQV key domain parameters do not have Q set"); 
    BigInteger bigInteger = calculateDHMQVAgreement(dHPrivateKeyParameters.getParameters(), dHPrivateKeyParameters, dHMQVPublicParameters.getStaticPublicKey(), this.privParams.getEphemeralPrivateKey(), this.privParams.getEphemeralPublicKey(), dHMQVPublicParameters.getEphemeralPublicKey());
    if (bigInteger.equals(ONE))
      throw new IllegalStateException("1 is not a valid agreement value for MQV"); 
    return bigInteger;
  }
  
  private BigInteger calculateDHMQVAgreement(DHParameters paramDHParameters, DHPrivateKeyParameters paramDHPrivateKeyParameters1, DHPublicKeyParameters paramDHPublicKeyParameters1, DHPrivateKeyParameters paramDHPrivateKeyParameters2, DHPublicKeyParameters paramDHPublicKeyParameters2, DHPublicKeyParameters paramDHPublicKeyParameters3) {
    BigInteger bigInteger1 = paramDHParameters.getQ();
    int i = (bigInteger1.bitLength() + 1) / 2;
    BigInteger bigInteger2 = BigInteger.valueOf(2L).pow(i);
    BigInteger bigInteger3 = paramDHPublicKeyParameters2.getY().mod(bigInteger2).add(bigInteger2);
    BigInteger bigInteger4 = paramDHPrivateKeyParameters2.getX().add(bigInteger3.multiply(paramDHPrivateKeyParameters1.getX())).mod(bigInteger1);
    BigInteger bigInteger5 = paramDHPublicKeyParameters3.getY().mod(bigInteger2).add(bigInteger2);
    return paramDHPublicKeyParameters3.getY().multiply(paramDHPublicKeyParameters1.getY().modPow(bigInteger5, paramDHParameters.getP())).modPow(bigInteger4, paramDHParameters.getP());
  }
}
