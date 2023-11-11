package org.bouncycastle.jcajce.provider.asymmetric.ecgost12;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.spec.GOST3410ParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
  Object ecParams = null;
  
  ECKeyPairGenerator engine = new ECKeyPairGenerator();
  
  String algorithm = "ECGOST3410-2012";
  
  ECKeyGenerationParameters param;
  
  int strength = 239;
  
  SecureRandom random = null;
  
  boolean initialised = false;
  
  public KeyPairGeneratorSpi() {
    super("ECGOST3410-2012");
  }
  
  public void initialize(int paramInt, SecureRandom paramSecureRandom) {
    this.strength = paramInt;
    this.random = paramSecureRandom;
    if (this.ecParams != null) {
      try {
        initialize((ECGenParameterSpec)this.ecParams, paramSecureRandom);
      } catch (InvalidAlgorithmParameterException invalidAlgorithmParameterException) {
        throw new InvalidParameterException("key size not configurable.");
      } 
    } else {
      throw new InvalidParameterException("unknown key size.");
    } 
  }
  
  public void initialize(AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidAlgorithmParameterException {
    if (paramAlgorithmParameterSpec instanceof GOST3410ParameterSpec) {
      GOST3410ParameterSpec gOST3410ParameterSpec = (GOST3410ParameterSpec)paramAlgorithmParameterSpec;
      init(gOST3410ParameterSpec, paramSecureRandom);
    } else if (paramAlgorithmParameterSpec instanceof ECParameterSpec) {
      ECParameterSpec eCParameterSpec = (ECParameterSpec)paramAlgorithmParameterSpec;
      this.ecParams = paramAlgorithmParameterSpec;
      this.param = new ECKeyGenerationParameters(new ECDomainParameters(eCParameterSpec.getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH()), paramSecureRandom);
      this.engine.init(this.param);
      this.initialised = true;
    } else if (paramAlgorithmParameterSpec instanceof ECParameterSpec) {
      ECParameterSpec eCParameterSpec = (ECParameterSpec)paramAlgorithmParameterSpec;
      this.ecParams = paramAlgorithmParameterSpec;
      ECCurve eCCurve = EC5Util.convertCurve(eCParameterSpec.getCurve());
      ECPoint eCPoint = EC5Util.convertPoint(eCCurve, eCParameterSpec.getGenerator());
      this.param = new ECKeyGenerationParameters(new ECDomainParameters(eCCurve, eCPoint, eCParameterSpec.getOrder(), BigInteger.valueOf(eCParameterSpec.getCofactor())), paramSecureRandom);
      this.engine.init(this.param);
      this.initialised = true;
    } else if (paramAlgorithmParameterSpec instanceof ECGenParameterSpec || paramAlgorithmParameterSpec instanceof ECNamedCurveGenParameterSpec) {
      String str;
      if (paramAlgorithmParameterSpec instanceof ECGenParameterSpec) {
        str = ((ECGenParameterSpec)paramAlgorithmParameterSpec).getName();
      } else {
        str = ((ECNamedCurveGenParameterSpec)paramAlgorithmParameterSpec).getName();
      } 
      init(new GOST3410ParameterSpec(str), paramSecureRandom);
    } else if (paramAlgorithmParameterSpec == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() != null) {
      ECParameterSpec eCParameterSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
      this.ecParams = paramAlgorithmParameterSpec;
      this.param = new ECKeyGenerationParameters(new ECDomainParameters(eCParameterSpec.getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH()), paramSecureRandom);
      this.engine.init(this.param);
      this.initialised = true;
    } else {
      if (paramAlgorithmParameterSpec == null && BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa() == null)
        throw new InvalidAlgorithmParameterException("null parameter passed but no implicitCA set"); 
      throw new InvalidAlgorithmParameterException("parameter object not a ECParameterSpec: " + paramAlgorithmParameterSpec.getClass().getName());
    } 
  }
  
  private void init(GOST3410ParameterSpec paramGOST3410ParameterSpec, SecureRandom paramSecureRandom) throws InvalidAlgorithmParameterException {
    X9ECParameters x9ECParameters = ECGOST3410NamedCurves.getByOIDX9(paramGOST3410ParameterSpec.getPublicKeyParamSet());
    if (x9ECParameters == null)
      throw new InvalidAlgorithmParameterException("unknown curve: " + paramGOST3410ParameterSpec.getPublicKeyParamSet()); 
    this.ecParams = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(paramGOST3410ParameterSpec.getPublicKeyParamSet()), x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH(), x9ECParameters.getSeed());
    this.param = new ECKeyGenerationParameters(new ECGOST3410Parameters(new ECNamedDomainParameters(paramGOST3410ParameterSpec.getPublicKeyParamSet(), x9ECParameters), paramGOST3410ParameterSpec.getPublicKeyParamSet(), paramGOST3410ParameterSpec.getDigestParamSet(), paramGOST3410ParameterSpec.getEncryptionParamSet()), paramSecureRandom);
    this.engine.init(this.param);
    this.initialised = true;
  }
  
  public KeyPair generateKeyPair() {
    if (!this.initialised)
      throw new IllegalStateException("EC Key Pair Generator not initialised"); 
    AsymmetricCipherKeyPair asymmetricCipherKeyPair = this.engine.generateKeyPair();
    ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters)asymmetricCipherKeyPair.getPublic();
    ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters)asymmetricCipherKeyPair.getPrivate();
    if (this.ecParams instanceof ECParameterSpec) {
      ECParameterSpec eCParameterSpec1 = (ECParameterSpec)this.ecParams;
      BCECGOST3410_2012PublicKey bCECGOST3410_2012PublicKey1 = new BCECGOST3410_2012PublicKey(this.algorithm, eCPublicKeyParameters, eCParameterSpec1);
      return new KeyPair(bCECGOST3410_2012PublicKey1, new BCECGOST3410_2012PrivateKey(this.algorithm, eCPrivateKeyParameters, bCECGOST3410_2012PublicKey1, eCParameterSpec1));
    } 
    if (this.ecParams == null)
      return new KeyPair(new BCECGOST3410_2012PublicKey(this.algorithm, eCPublicKeyParameters), new BCECGOST3410_2012PrivateKey(this.algorithm, eCPrivateKeyParameters)); 
    ECParameterSpec eCParameterSpec = (ECParameterSpec)this.ecParams;
    BCECGOST3410_2012PublicKey bCECGOST3410_2012PublicKey = new BCECGOST3410_2012PublicKey(this.algorithm, eCPublicKeyParameters, eCParameterSpec);
    return new KeyPair(bCECGOST3410_2012PublicKey, new BCECGOST3410_2012PrivateKey(this.algorithm, eCPrivateKeyParameters, bCECGOST3410_2012PublicKey, eCParameterSpec));
  }
}
