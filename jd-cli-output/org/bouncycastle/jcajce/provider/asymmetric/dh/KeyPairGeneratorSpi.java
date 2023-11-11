package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Hashtable;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Integers;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
  private static Hashtable params = new Hashtable<Object, Object>();
  
  private static Object lock = new Object();
  
  DHKeyGenerationParameters param;
  
  DHBasicKeyPairGenerator engine = new DHBasicKeyPairGenerator();
  
  int strength = 2048;
  
  SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
  
  boolean initialised = false;
  
  public KeyPairGeneratorSpi() {
    super("DH");
  }
  
  public void initialize(int paramInt, SecureRandom paramSecureRandom) {
    this.strength = paramInt;
    this.random = paramSecureRandom;
    this.initialised = false;
  }
  
  public void initialize(AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidAlgorithmParameterException {
    if (!(paramAlgorithmParameterSpec instanceof DHParameterSpec))
      throw new InvalidAlgorithmParameterException("parameter object not a DHParameterSpec"); 
    DHParameterSpec dHParameterSpec = (DHParameterSpec)paramAlgorithmParameterSpec;
    try {
      this.param = convertParams(paramSecureRandom, dHParameterSpec);
    } catch (IllegalArgumentException illegalArgumentException) {
      throw new InvalidAlgorithmParameterException(illegalArgumentException.getMessage(), illegalArgumentException);
    } 
    this.engine.init(this.param);
    this.initialised = true;
  }
  
  private DHKeyGenerationParameters convertParams(SecureRandom paramSecureRandom, DHParameterSpec paramDHParameterSpec) {
    return (paramDHParameterSpec instanceof DHDomainParameterSpec) ? new DHKeyGenerationParameters(paramSecureRandom, ((DHDomainParameterSpec)paramDHParameterSpec).getDomainParameters()) : new DHKeyGenerationParameters(paramSecureRandom, new DHParameters(paramDHParameterSpec.getP(), paramDHParameterSpec.getG(), null, paramDHParameterSpec.getL()));
  }
  
  public KeyPair generateKeyPair() {
    if (!this.initialised) {
      Integer integer = Integers.valueOf(this.strength);
      if (params.containsKey(integer)) {
        this.param = (DHKeyGenerationParameters)params.get(integer);
      } else {
        DHParameterSpec dHParameterSpec = BouncyCastleProvider.CONFIGURATION.getDHDefaultParameters(this.strength);
        if (dHParameterSpec != null) {
          this.param = convertParams(this.random, dHParameterSpec);
        } else {
          synchronized (lock) {
            if (params.containsKey(integer)) {
              this.param = (DHKeyGenerationParameters)params.get(integer);
            } else {
              DHParametersGenerator dHParametersGenerator = new DHParametersGenerator();
              dHParametersGenerator.init(this.strength, PrimeCertaintyCalculator.getDefaultCertainty(this.strength), this.random);
              this.param = new DHKeyGenerationParameters(this.random, dHParametersGenerator.generateParameters());
              params.put(integer, this.param);
            } 
          } 
        } 
      } 
      this.engine.init(this.param);
      this.initialised = true;
    } 
    AsymmetricCipherKeyPair asymmetricCipherKeyPair = this.engine.generateKeyPair();
    DHPublicKeyParameters dHPublicKeyParameters = (DHPublicKeyParameters)asymmetricCipherKeyPair.getPublic();
    DHPrivateKeyParameters dHPrivateKeyParameters = (DHPrivateKeyParameters)asymmetricCipherKeyPair.getPrivate();
    return new KeyPair(new BCDHPublicKey(dHPublicKeyParameters), new BCDHPrivateKey(dHPrivateKeyParameters));
  }
}
