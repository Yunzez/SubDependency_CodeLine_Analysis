package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
import org.bouncycastle.util.Integers;

public class KeyPairGeneratorSpi extends KeyPairGenerator {
  private static final Map catLookup = new HashMap<Object, Object>();
  
  private QTESLAKeyGenerationParameters param;
  
  private QTESLAKeyPairGenerator engine = new QTESLAKeyPairGenerator();
  
  private SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
  
  private boolean initialised = false;
  
  public KeyPairGeneratorSpi() {
    super("qTESLA");
  }
  
  public void initialize(int paramInt, SecureRandom paramSecureRandom) {
    throw new IllegalArgumentException("use AlgorithmParameterSpec");
  }
  
  public void initialize(AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidAlgorithmParameterException {
    if (!(paramAlgorithmParameterSpec instanceof QTESLAParameterSpec))
      throw new InvalidAlgorithmParameterException("parameter object not a QTESLAParameterSpec"); 
    QTESLAParameterSpec qTESLAParameterSpec = (QTESLAParameterSpec)paramAlgorithmParameterSpec;
    this.param = new QTESLAKeyGenerationParameters(((Integer)catLookup.get(qTESLAParameterSpec.getSecurityCategory())).intValue(), paramSecureRandom);
    this.engine.init(this.param);
    this.initialised = true;
  }
  
  public KeyPair generateKeyPair() {
    if (!this.initialised) {
      this.param = new QTESLAKeyGenerationParameters(6, this.random);
      this.engine.init(this.param);
      this.initialised = true;
    } 
    AsymmetricCipherKeyPair asymmetricCipherKeyPair = this.engine.generateKeyPair();
    QTESLAPublicKeyParameters qTESLAPublicKeyParameters = (QTESLAPublicKeyParameters)asymmetricCipherKeyPair.getPublic();
    QTESLAPrivateKeyParameters qTESLAPrivateKeyParameters = (QTESLAPrivateKeyParameters)asymmetricCipherKeyPair.getPrivate();
    return new KeyPair(new BCqTESLAPublicKey(qTESLAPublicKeyParameters), new BCqTESLAPrivateKey(qTESLAPrivateKeyParameters));
  }
  
  static {
    catLookup.put(QTESLASecurityCategory.getName(5), Integers.valueOf(5));
    catLookup.put(QTESLASecurityCategory.getName(6), Integers.valueOf(6));
  }
}
