package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.agreement.DHUnifiedAgreement;
import org.bouncycastle.crypto.agreement.MQVBasicAgreement;
import org.bouncycastle.crypto.agreement.kdf.ConcatenationKDFGenerator;
import org.bouncycastle.crypto.agreement.kdf.DHKEKGenerator;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.DHUPrivateParameters;
import org.bouncycastle.crypto.params.DHUPublicParameters;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;

public class KeyAgreementSpi extends BaseAgreementSpi {
  private static final BigInteger ONE = BigInteger.valueOf(1L);
  
  private static final BigInteger TWO = BigInteger.valueOf(2L);
  
  private final DHUnifiedAgreement unifiedAgreement = null;
  
  private final BasicAgreement mqvAgreement = null;
  
  private DHUParameterSpec dheParameters;
  
  private MQVParameterSpec mqvParameters;
  
  private BigInteger x;
  
  private BigInteger p;
  
  private BigInteger g;
  
  private byte[] result;
  
  public KeyAgreementSpi() {
    this("Diffie-Hellman", (DerivationFunction)null);
  }
  
  public KeyAgreementSpi(String paramString, DerivationFunction paramDerivationFunction) {
    super(paramString, paramDerivationFunction);
  }
  
  public KeyAgreementSpi(String paramString, DHUnifiedAgreement paramDHUnifiedAgreement, DerivationFunction paramDerivationFunction) {
    super(paramString, paramDerivationFunction);
  }
  
  public KeyAgreementSpi(String paramString, BasicAgreement paramBasicAgreement, DerivationFunction paramDerivationFunction) {
    super(paramString, paramDerivationFunction);
  }
  
  protected byte[] bigIntToBytes(BigInteger paramBigInteger) {
    int i = (this.p.bitLength() + 7) / 8;
    byte[] arrayOfByte1 = paramBigInteger.toByteArray();
    if (arrayOfByte1.length == i)
      return arrayOfByte1; 
    if (arrayOfByte1[0] == 0 && arrayOfByte1.length == i + 1) {
      byte[] arrayOfByte = new byte[arrayOfByte1.length - 1];
      System.arraycopy(arrayOfByte1, 1, arrayOfByte, 0, arrayOfByte.length);
      return arrayOfByte;
    } 
    byte[] arrayOfByte2 = new byte[i];
    System.arraycopy(arrayOfByte1, 0, arrayOfByte2, arrayOfByte2.length - arrayOfByte1.length, arrayOfByte1.length);
    return arrayOfByte2;
  }
  
  protected Key engineDoPhase(Key paramKey, boolean paramBoolean) throws InvalidKeyException, IllegalStateException {
    if (this.x == null)
      throw new IllegalStateException("Diffie-Hellman not initialised."); 
    if (!(paramKey instanceof DHPublicKey))
      throw new InvalidKeyException("DHKeyAgreement doPhase requires DHPublicKey"); 
    DHPublicKey dHPublicKey = (DHPublicKey)paramKey;
    if (!dHPublicKey.getParams().getG().equals(this.g) || !dHPublicKey.getParams().getP().equals(this.p))
      throw new InvalidKeyException("DHPublicKey not for this KeyAgreement!"); 
    BigInteger bigInteger1 = ((DHPublicKey)paramKey).getY();
    if (bigInteger1 == null || bigInteger1.compareTo(TWO) < 0 || bigInteger1.compareTo(this.p.subtract(ONE)) >= 0)
      throw new InvalidKeyException("Invalid DH PublicKey"); 
    if (this.unifiedAgreement != null) {
      if (!paramBoolean)
        throw new IllegalStateException("unified Diffie-Hellman can use only two key pairs"); 
      DHPublicKeyParameters dHPublicKeyParameters1 = generatePublicKeyParameter((PublicKey)paramKey);
      DHPublicKeyParameters dHPublicKeyParameters2 = generatePublicKeyParameter(this.dheParameters.getOtherPartyEphemeralKey());
      DHUPublicParameters dHUPublicParameters = new DHUPublicParameters(dHPublicKeyParameters1, dHPublicKeyParameters2);
      this.result = this.unifiedAgreement.calculateAgreement(dHUPublicParameters);
      return null;
    } 
    if (this.mqvAgreement != null) {
      if (!paramBoolean)
        throw new IllegalStateException("MQV Diffie-Hellman can use only two key pairs"); 
      DHPublicKeyParameters dHPublicKeyParameters1 = generatePublicKeyParameter((PublicKey)paramKey);
      DHPublicKeyParameters dHPublicKeyParameters2 = generatePublicKeyParameter(this.mqvParameters.getOtherPartyEphemeralKey());
      DHMQVPublicParameters dHMQVPublicParameters = new DHMQVPublicParameters(dHPublicKeyParameters1, dHPublicKeyParameters2);
      this.result = bigIntToBytes(this.mqvAgreement.calculateAgreement(dHMQVPublicParameters));
      return null;
    } 
    BigInteger bigInteger2 = bigInteger1.modPow(this.x, this.p);
    if (bigInteger2.compareTo(ONE) == 0)
      throw new InvalidKeyException("Shared key can't be 1"); 
    this.result = bigIntToBytes(bigInteger2);
    return paramBoolean ? null : new BCDHPublicKey(bigInteger2, dHPublicKey.getParams());
  }
  
  protected byte[] engineGenerateSecret() throws IllegalStateException {
    if (this.x == null)
      throw new IllegalStateException("Diffie-Hellman not initialised."); 
    return super.engineGenerateSecret();
  }
  
  protected int engineGenerateSecret(byte[] paramArrayOfbyte, int paramInt) throws IllegalStateException, ShortBufferException {
    if (this.x == null)
      throw new IllegalStateException("Diffie-Hellman not initialised."); 
    return super.engineGenerateSecret(paramArrayOfbyte, paramInt);
  }
  
  protected SecretKey engineGenerateSecret(String paramString) throws NoSuchAlgorithmException {
    if (this.x == null)
      throw new IllegalStateException("Diffie-Hellman not initialised."); 
    return paramString.equals("TlsPremasterSecret") ? new SecretKeySpec(trimZeroes(this.result), paramString) : super.engineGenerateSecret(paramString);
  }
  
  protected void engineInit(Key paramKey, AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (!(paramKey instanceof DHPrivateKey))
      throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey for initialisation"); 
    DHPrivateKey dHPrivateKey = (DHPrivateKey)paramKey;
    if (paramAlgorithmParameterSpec != null) {
      if (paramAlgorithmParameterSpec instanceof DHParameterSpec) {
        DHParameterSpec dHParameterSpec = (DHParameterSpec)paramAlgorithmParameterSpec;
        this.p = dHParameterSpec.getP();
        this.g = dHParameterSpec.getG();
        this.dheParameters = null;
        this.ukmParameters = null;
      } else if (paramAlgorithmParameterSpec instanceof DHUParameterSpec) {
        if (this.unifiedAgreement == null)
          throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based"); 
        this.p = dHPrivateKey.getParams().getP();
        this.g = dHPrivateKey.getParams().getG();
        this.dheParameters = (DHUParameterSpec)paramAlgorithmParameterSpec;
        this.ukmParameters = ((DHUParameterSpec)paramAlgorithmParameterSpec).getUserKeyingMaterial();
        if (this.dheParameters.getEphemeralPublicKey() != null) {
          this.unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.dheParameters.getEphemeralPrivateKey()), generatePublicKeyParameter(this.dheParameters.getEphemeralPublicKey())));
        } else {
          this.unifiedAgreement.init(new DHUPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.dheParameters.getEphemeralPrivateKey())));
        } 
      } else if (paramAlgorithmParameterSpec instanceof MQVParameterSpec) {
        if (this.mqvAgreement == null)
          throw new InvalidAlgorithmParameterException("agreement algorithm not MQV based"); 
        this.p = dHPrivateKey.getParams().getP();
        this.g = dHPrivateKey.getParams().getG();
        this.mqvParameters = (MQVParameterSpec)paramAlgorithmParameterSpec;
        this.ukmParameters = ((MQVParameterSpec)paramAlgorithmParameterSpec).getUserKeyingMaterial();
        if (this.mqvParameters.getEphemeralPublicKey() != null) {
          this.mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.mqvParameters.getEphemeralPrivateKey()), generatePublicKeyParameter(this.mqvParameters.getEphemeralPublicKey())));
        } else {
          this.mqvAgreement.init(new DHMQVPrivateParameters(generatePrivateKeyParameter(dHPrivateKey), generatePrivateKeyParameter(this.mqvParameters.getEphemeralPrivateKey())));
        } 
      } else if (paramAlgorithmParameterSpec instanceof UserKeyingMaterialSpec) {
        if (this.kdf == null)
          throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec"); 
        this.p = dHPrivateKey.getParams().getP();
        this.g = dHPrivateKey.getParams().getG();
        this.dheParameters = null;
        this.ukmParameters = ((UserKeyingMaterialSpec)paramAlgorithmParameterSpec).getUserKeyingMaterial();
      } else {
        throw new InvalidAlgorithmParameterException("DHKeyAgreement only accepts DHParameterSpec");
      } 
    } else {
      this.p = dHPrivateKey.getParams().getP();
      this.g = dHPrivateKey.getParams().getG();
    } 
    this.x = dHPrivateKey.getX();
    this.result = bigIntToBytes(this.x);
  }
  
  protected void engineInit(Key paramKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    if (!(paramKey instanceof DHPrivateKey))
      throw new InvalidKeyException("DHKeyAgreement requires DHPrivateKey"); 
    DHPrivateKey dHPrivateKey = (DHPrivateKey)paramKey;
    this.p = dHPrivateKey.getParams().getP();
    this.g = dHPrivateKey.getParams().getG();
    this.x = dHPrivateKey.getX();
    this.result = bigIntToBytes(this.x);
  }
  
  protected byte[] calcSecret() {
    return this.result;
  }
  
  private DHPrivateKeyParameters generatePrivateKeyParameter(PrivateKey paramPrivateKey) throws InvalidKeyException {
    if (paramPrivateKey instanceof DHPrivateKey) {
      if (paramPrivateKey instanceof BCDHPrivateKey)
        return ((BCDHPrivateKey)paramPrivateKey).engineGetKeyParameters(); 
      DHPrivateKey dHPrivateKey = (DHPrivateKey)paramPrivateKey;
      DHParameterSpec dHParameterSpec = dHPrivateKey.getParams();
      return new DHPrivateKeyParameters(dHPrivateKey.getX(), new DHParameters(dHParameterSpec.getP(), dHParameterSpec.getG(), null, dHParameterSpec.getL()));
    } 
    throw new InvalidKeyException("private key not a DHPrivateKey");
  }
  
  private DHPublicKeyParameters generatePublicKeyParameter(PublicKey paramPublicKey) throws InvalidKeyException {
    if (paramPublicKey instanceof DHPublicKey) {
      if (paramPublicKey instanceof BCDHPublicKey)
        return ((BCDHPublicKey)paramPublicKey).engineGetKeyParameters(); 
      DHPublicKey dHPublicKey = (DHPublicKey)paramPublicKey;
      DHParameterSpec dHParameterSpec = dHPublicKey.getParams();
      return (dHParameterSpec instanceof DHDomainParameterSpec) ? new DHPublicKeyParameters(dHPublicKey.getY(), ((DHDomainParameterSpec)dHParameterSpec).getDomainParameters()) : new DHPublicKeyParameters(dHPublicKey.getY(), new DHParameters(dHParameterSpec.getP(), dHParameterSpec.getG(), null, dHParameterSpec.getL()));
    } 
    throw new InvalidKeyException("public key not a DHPublicKey");
  }
  
  public static class DHUwithSHA1CKDF extends KeyAgreementSpi {
    public DHUwithSHA1CKDF() {
      super("DHUwithSHA1CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
    }
  }
  
  public static class DHUwithSHA1KDF extends KeyAgreementSpi {
    public DHUwithSHA1KDF() {
      super("DHUwithSHA1KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()));
    }
  }
  
  public static class DHUwithSHA224CKDF extends KeyAgreementSpi {
    public DHUwithSHA224CKDF() {
      super("DHUwithSHA224CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
    }
  }
  
  public static class DHUwithSHA224KDF extends KeyAgreementSpi {
    public DHUwithSHA224KDF() {
      super("DHUwithSHA224KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()));
    }
  }
  
  public static class DHUwithSHA256CKDF extends KeyAgreementSpi {
    public DHUwithSHA256CKDF() {
      super("DHUwithSHA256CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
    }
  }
  
  public static class DHUwithSHA256KDF extends KeyAgreementSpi {
    public DHUwithSHA256KDF() {
      super("DHUwithSHA256KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()));
    }
  }
  
  public static class DHUwithSHA384CKDF extends KeyAgreementSpi {
    public DHUwithSHA384CKDF() {
      super("DHUwithSHA384CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
    }
  }
  
  public static class DHUwithSHA384KDF extends KeyAgreementSpi {
    public DHUwithSHA384KDF() {
      super("DHUwithSHA384KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()));
    }
  }
  
  public static class DHUwithSHA512CKDF extends KeyAgreementSpi {
    public DHUwithSHA512CKDF() {
      super("DHUwithSHA512CKDF", new DHUnifiedAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
    }
  }
  
  public static class DHUwithSHA512KDF extends KeyAgreementSpi {
    public DHUwithSHA512KDF() {
      super("DHUwithSHA512KDF", new DHUnifiedAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()));
    }
  }
  
  public static class DHwithRFC2631KDF extends KeyAgreementSpi {
    public DHwithRFC2631KDF() {
      super("DHwithRFC2631KDF", new DHKEKGenerator(DigestFactory.createSHA1()));
    }
  }
  
  public static class DHwithSHA1CKDF extends KeyAgreementSpi {
    public DHwithSHA1CKDF() {
      super("DHwithSHA1CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
    }
  }
  
  public static class DHwithSHA1KDF extends KeyAgreementSpi {
    public DHwithSHA1KDF() {
      super("DHwithSHA1CKDF", new KDF2BytesGenerator(DigestFactory.createSHA1()));
    }
  }
  
  public static class DHwithSHA224CKDF extends KeyAgreementSpi {
    public DHwithSHA224CKDF() {
      super("DHwithSHA224CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
    }
  }
  
  public static class DHwithSHA224KDF extends KeyAgreementSpi {
    public DHwithSHA224KDF() {
      super("DHwithSHA224CKDF", new KDF2BytesGenerator(DigestFactory.createSHA224()));
    }
  }
  
  public static class DHwithSHA256CKDF extends KeyAgreementSpi {
    public DHwithSHA256CKDF() {
      super("DHwithSHA256CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
    }
  }
  
  public static class DHwithSHA256KDF extends KeyAgreementSpi {
    public DHwithSHA256KDF() {
      super("DHwithSHA256CKDF", new KDF2BytesGenerator(DigestFactory.createSHA256()));
    }
  }
  
  public static class DHwithSHA384CKDF extends KeyAgreementSpi {
    public DHwithSHA384CKDF() {
      super("DHwithSHA384CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
    }
  }
  
  public static class DHwithSHA384KDF extends KeyAgreementSpi {
    public DHwithSHA384KDF() {
      super("DHwithSHA384KDF", new KDF2BytesGenerator(DigestFactory.createSHA384()));
    }
  }
  
  public static class DHwithSHA512CKDF extends KeyAgreementSpi {
    public DHwithSHA512CKDF() {
      super("DHwithSHA512CKDF", new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
    }
  }
  
  public static class DHwithSHA512KDF extends KeyAgreementSpi {
    public DHwithSHA512KDF() {
      super("DHwithSHA512KDF", new KDF2BytesGenerator(DigestFactory.createSHA512()));
    }
  }
  
  public static class MQVwithSHA1CKDF extends KeyAgreementSpi {
    public MQVwithSHA1CKDF() {
      super("MQVwithSHA1CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA1()));
    }
  }
  
  public static class MQVwithSHA1KDF extends KeyAgreementSpi {
    public MQVwithSHA1KDF() {
      super("MQVwithSHA1KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA1()));
    }
  }
  
  public static class MQVwithSHA224CKDF extends KeyAgreementSpi {
    public MQVwithSHA224CKDF() {
      super("MQVwithSHA224CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA224()));
    }
  }
  
  public static class MQVwithSHA224KDF extends KeyAgreementSpi {
    public MQVwithSHA224KDF() {
      super("MQVwithSHA224KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA224()));
    }
  }
  
  public static class MQVwithSHA256CKDF extends KeyAgreementSpi {
    public MQVwithSHA256CKDF() {
      super("MQVwithSHA256CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA256()));
    }
  }
  
  public static class MQVwithSHA256KDF extends KeyAgreementSpi {
    public MQVwithSHA256KDF() {
      super("MQVwithSHA256KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA256()));
    }
  }
  
  public static class MQVwithSHA384CKDF extends KeyAgreementSpi {
    public MQVwithSHA384CKDF() {
      super("MQVwithSHA384CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA384()));
    }
  }
  
  public static class MQVwithSHA384KDF extends KeyAgreementSpi {
    public MQVwithSHA384KDF() {
      super("MQVwithSHA384KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA384()));
    }
  }
  
  public static class MQVwithSHA512CKDF extends KeyAgreementSpi {
    public MQVwithSHA512CKDF() {
      super("MQVwithSHA512CKDF", new MQVBasicAgreement(), new ConcatenationKDFGenerator(DigestFactory.createSHA512()));
    }
  }
  
  public static class MQVwithSHA512KDF extends KeyAgreementSpi {
    public MQVwithSHA512KDF() {
      super("MQVwithSHA512KDF", new MQVBasicAgreement(), new KDF2BytesGenerator(DigestFactory.createSHA512()));
    }
  }
}
