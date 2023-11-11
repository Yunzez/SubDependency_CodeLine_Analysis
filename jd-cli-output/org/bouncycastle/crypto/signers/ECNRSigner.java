package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public class ECNRSigner implements DSAExt {
  private boolean forSigning;
  
  private ECKeyParameters key;
  
  private SecureRandom random;
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    this.forSigning = paramBoolean;
    if (paramBoolean) {
      if (paramCipherParameters instanceof ParametersWithRandom) {
        ParametersWithRandom parametersWithRandom = (ParametersWithRandom)paramCipherParameters;
        this.random = parametersWithRandom.getRandom();
        this.key = (ECPrivateKeyParameters)parametersWithRandom.getParameters();
      } else {
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.key = (ECPrivateKeyParameters)paramCipherParameters;
      } 
    } else {
      this.key = (ECPublicKeyParameters)paramCipherParameters;
    } 
  }
  
  public BigInteger getOrder() {
    return this.key.getParameters().getN();
  }
  
  public BigInteger[] generateSignature(byte[] paramArrayOfbyte) {
    if (!this.forSigning)
      throw new IllegalStateException("not initialised for signing"); 
    BigInteger bigInteger1 = getOrder();
    BigInteger bigInteger2 = new BigInteger(1, paramArrayOfbyte);
    ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)this.key;
    if (bigInteger2.compareTo(bigInteger1) >= 0)
      throw new DataLengthException("input too large for ECNR key"); 
    BigInteger bigInteger3 = null;
    BigInteger bigInteger4 = null;
    while (true) {
      ECKeyPairGenerator eCKeyPairGenerator = new ECKeyPairGenerator();
      eCKeyPairGenerator.init(new ECKeyGenerationParameters(eCPrivateKeyParameters.getParameters(), this.random));
      AsymmetricCipherKeyPair asymmetricCipherKeyPair = eCKeyPairGenerator.generateKeyPair();
      ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters)asymmetricCipherKeyPair.getPublic();
      BigInteger bigInteger = eCPublicKeyParameters.getQ().getAffineXCoord().toBigInteger();
      bigInteger3 = bigInteger.add(bigInteger2).mod(bigInteger1);
      if (!bigInteger3.equals(ECConstants.ZERO)) {
        BigInteger bigInteger5 = eCPrivateKeyParameters.getD();
        BigInteger bigInteger6 = ((ECPrivateKeyParameters)asymmetricCipherKeyPair.getPrivate()).getD();
        bigInteger4 = bigInteger6.subtract(bigInteger3.multiply(bigInteger5)).mod(bigInteger1);
        BigInteger[] arrayOfBigInteger = new BigInteger[2];
        arrayOfBigInteger[0] = bigInteger3;
        arrayOfBigInteger[1] = bigInteger4;
        return arrayOfBigInteger;
      } 
    } 
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte, BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (this.forSigning)
      throw new IllegalStateException("not initialised for verifying"); 
    ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters)this.key;
    BigInteger bigInteger1 = eCPublicKeyParameters.getParameters().getN();
    int i = bigInteger1.bitLength();
    BigInteger bigInteger2 = new BigInteger(1, paramArrayOfbyte);
    int j = bigInteger2.bitLength();
    if (j > i)
      throw new DataLengthException("input too large for ECNR key."); 
    BigInteger bigInteger3 = extractT(eCPublicKeyParameters, paramBigInteger1, paramBigInteger2);
    return (bigInteger3 != null && bigInteger3.equals(bigInteger2.mod(bigInteger1)));
  }
  
  public byte[] getRecoveredMessage(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (this.forSigning)
      throw new IllegalStateException("not initialised for verifying/recovery"); 
    BigInteger bigInteger = extractT((ECPublicKeyParameters)this.key, paramBigInteger1, paramBigInteger2);
    return (bigInteger != null) ? BigIntegers.asUnsignedByteArray(bigInteger) : null;
  }
  
  private BigInteger extractT(ECPublicKeyParameters paramECPublicKeyParameters, BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    BigInteger bigInteger1 = paramECPublicKeyParameters.getParameters().getN();
    if (paramBigInteger1.compareTo(ECConstants.ONE) < 0 || paramBigInteger1.compareTo(bigInteger1) >= 0)
      return null; 
    if (paramBigInteger2.compareTo(ECConstants.ZERO) < 0 || paramBigInteger2.compareTo(bigInteger1) >= 0)
      return null; 
    ECPoint eCPoint1 = paramECPublicKeyParameters.getParameters().getG();
    ECPoint eCPoint2 = paramECPublicKeyParameters.getQ();
    ECPoint eCPoint3 = ECAlgorithms.sumOfTwoMultiplies(eCPoint1, paramBigInteger2, eCPoint2, paramBigInteger1).normalize();
    if (eCPoint3.isInfinity())
      return null; 
    BigInteger bigInteger2 = eCPoint3.getAffineXCoord().toBigInteger();
    return paramBigInteger1.subtract(bigInteger2).mod(bigInteger1);
  }
}
