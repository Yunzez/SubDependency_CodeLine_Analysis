package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
  private static final AlgorithmIdentifier PKCS_ALGID = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
  
  private static final AlgorithmIdentifier PSS_ALGID = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS);
  
  static final BigInteger defaultPublicExponent = BigInteger.valueOf(65537L);
  
  RSAKeyGenerationParameters param;
  
  RSAKeyPairGenerator engine;
  
  AlgorithmIdentifier algId;
  
  public KeyPairGeneratorSpi(String paramString, AlgorithmIdentifier paramAlgorithmIdentifier) {
    super(paramString);
    this.algId = paramAlgorithmIdentifier;
    this.engine = new RSAKeyPairGenerator();
    this.param = new RSAKeyGenerationParameters(defaultPublicExponent, CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048));
    this.engine.init(this.param);
  }
  
  public KeyPairGeneratorSpi() {
    this("RSA", PKCS_ALGID);
  }
  
  public void initialize(int paramInt, SecureRandom paramSecureRandom) {
    this.param = new RSAKeyGenerationParameters(defaultPublicExponent, paramSecureRandom, paramInt, PrimeCertaintyCalculator.getDefaultCertainty(paramInt));
    this.engine.init(this.param);
  }
  
  public void initialize(AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidAlgorithmParameterException {
    if (!(paramAlgorithmParameterSpec instanceof RSAKeyGenParameterSpec))
      throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec"); 
    RSAKeyGenParameterSpec rSAKeyGenParameterSpec = (RSAKeyGenParameterSpec)paramAlgorithmParameterSpec;
    this.param = new RSAKeyGenerationParameters(rSAKeyGenParameterSpec.getPublicExponent(), paramSecureRandom, rSAKeyGenParameterSpec.getKeysize(), PrimeCertaintyCalculator.getDefaultCertainty(2048));
    this.engine.init(this.param);
  }
  
  public KeyPair generateKeyPair() {
    AsymmetricCipherKeyPair asymmetricCipherKeyPair = this.engine.generateKeyPair();
    RSAKeyParameters rSAKeyParameters = (RSAKeyParameters)asymmetricCipherKeyPair.getPublic();
    RSAPrivateCrtKeyParameters rSAPrivateCrtKeyParameters = (RSAPrivateCrtKeyParameters)asymmetricCipherKeyPair.getPrivate();
    return new KeyPair(new BCRSAPublicKey(this.algId, rSAKeyParameters), new BCRSAPrivateCrtKey(this.algId, rSAPrivateCrtKeyParameters));
  }
  
  public static class PSS extends KeyPairGeneratorSpi {
    public PSS() {
      super("RSASSA-PSS", KeyPairGeneratorSpi.PSS_ALGID);
    }
  }
}
