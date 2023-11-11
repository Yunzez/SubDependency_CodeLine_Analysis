package META-INF.versions.11.org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.agreement.X448Agreement;
import org.bouncycastle.crypto.agreement.XDHUnifiedAgreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.params.XDHUPrivateParameters;
import org.bouncycastle.crypto.params.XDHUPublicParameters;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseAgreementSpi;
import org.bouncycastle.jcajce.spec.DHUParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class KeyAgreementSpi extends BaseAgreementSpi {
  private RawAgreement agreement;
  
  private DHUParameterSpec dhuSpec;
  
  private byte[] result;
  
  KeyAgreementSpi(String paramString) {
    super(paramString, null);
  }
  
  KeyAgreementSpi(String paramString, DerivationFunction paramDerivationFunction) {
    super(paramString, paramDerivationFunction);
  }
  
  protected byte[] calcSecret() {
    return this.result;
  }
  
  protected void engineInit(Key paramKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    AsymmetricKeyParameter asymmetricKeyParameter = getLwXDHKeyPrivate(paramKey);
    if (asymmetricKeyParameter instanceof X25519PrivateKeyParameters) {
      this.agreement = getAgreement("X25519");
    } else if (asymmetricKeyParameter instanceof X448PrivateKeyParameters) {
      this.agreement = getAgreement("X448");
    } else {
      throw new IllegalStateException("unsupported private key type");
    } 
    this.agreement.init(asymmetricKeyParameter);
    if (this.kdf != null) {
      this.ukmParameters = new byte[0];
    } else {
      this.ukmParameters = null;
    } 
  }
  
  protected void engineInit(Key paramKey, AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
    AsymmetricKeyParameter asymmetricKeyParameter = getLwXDHKeyPrivate(paramKey);
    if (asymmetricKeyParameter instanceof X25519PrivateKeyParameters) {
      this.agreement = getAgreement("X25519");
    } else if (asymmetricKeyParameter instanceof X448PrivateKeyParameters) {
      this.agreement = getAgreement("X448");
    } else {
      throw new IllegalStateException("unsupported private key type");
    } 
    this.ukmParameters = null;
    if (paramAlgorithmParameterSpec instanceof DHUParameterSpec) {
      if (this.kaAlgorithm.indexOf('U') < 0)
        throw new InvalidAlgorithmParameterException("agreement algorithm not DHU based"); 
      this.dhuSpec = (DHUParameterSpec)paramAlgorithmParameterSpec;
      this.ukmParameters = this.dhuSpec.getUserKeyingMaterial();
      this.agreement.init(new XDHUPrivateParameters(asymmetricKeyParameter, ((BCXDHPrivateKey)this.dhuSpec
            .getEphemeralPrivateKey()).engineGetKeyParameters(), ((BCXDHPublicKey)this.dhuSpec
            .getEphemeralPublicKey()).engineGetKeyParameters()));
    } else {
      this.agreement.init(asymmetricKeyParameter);
      if (paramAlgorithmParameterSpec instanceof UserKeyingMaterialSpec) {
        if (this.kdf == null)
          throw new InvalidAlgorithmParameterException("no KDF specified for UserKeyingMaterialSpec"); 
        this.ukmParameters = ((UserKeyingMaterialSpec)paramAlgorithmParameterSpec).getUserKeyingMaterial();
      } else {
        throw new InvalidAlgorithmParameterException("unknown ParameterSpec");
      } 
    } 
    if (this.kdf != null && this.ukmParameters == null)
      this.ukmParameters = new byte[0]; 
  }
  
  protected Key engineDoPhase(Key paramKey, boolean paramBoolean) throws InvalidKeyException, IllegalStateException {
    if (this.agreement == null)
      throw new IllegalStateException(this.kaAlgorithm + " not initialised."); 
    if (!paramBoolean)
      throw new IllegalStateException(this.kaAlgorithm + " can only be between two parties."); 
    AsymmetricKeyParameter asymmetricKeyParameter = getLwXDHKeyPublic(paramKey);
    this.result = new byte[this.agreement.getAgreementSize()];
    if (this.dhuSpec != null) {
      this.agreement.calculateAgreement(new XDHUPublicParameters(asymmetricKeyParameter, ((BCXDHPublicKey)this.dhuSpec.getOtherPartyEphemeralKey()).engineGetKeyParameters()), this.result, 0);
    } else {
      this.agreement.calculateAgreement(asymmetricKeyParameter, this.result, 0);
    } 
    return null;
  }
  
  private RawAgreement getAgreement(String paramString) throws InvalidKeyException {
    if (!this.kaAlgorithm.equals("XDH") && !this.kaAlgorithm.startsWith(paramString))
      throw new InvalidKeyException("inappropriate key for " + this.kaAlgorithm); 
    if (this.kaAlgorithm.indexOf('U') > 0) {
      if (paramString.startsWith("X448"))
        return new XDHUnifiedAgreement(new X448Agreement()); 
      return new XDHUnifiedAgreement(new X25519Agreement());
    } 
    if (paramString.startsWith("X448"))
      return new X448Agreement(); 
    return new X25519Agreement();
  }
  
  private static AsymmetricKeyParameter getLwXDHKeyPrivate(Key paramKey) throws InvalidKeyException {
    if (paramKey instanceof BCXDHPrivateKey)
      return ((BCXDHPrivateKey)paramKey).engineGetKeyParameters(); 
    if (paramKey instanceof XECPrivateKey) {
      XECPrivateKey xECPrivateKey = (XECPrivateKey)paramKey;
      Optional<byte[]> optional = xECPrivateKey.getScalar();
      if (!optional.isPresent())
        throw new InvalidKeyException("cannot use XEC private key without scalar"); 
      String str = xECPrivateKey.getAlgorithm();
      if ("X25519".equalsIgnoreCase(str))
        return getX25519PrivateKey(optional.get()); 
      if ("X448".equalsIgnoreCase(str))
        return getX448PrivateKey(optional.get()); 
      if ("XDH".equalsIgnoreCase(str)) {
        AlgorithmParameterSpec algorithmParameterSpec = xECPrivateKey.getParams();
        if (algorithmParameterSpec instanceof NamedParameterSpec) {
          NamedParameterSpec namedParameterSpec = (NamedParameterSpec)algorithmParameterSpec;
          String str1 = namedParameterSpec.getName();
          if ("X25519".equalsIgnoreCase(str1))
            return getX25519PrivateKey(optional.get()); 
          if ("X448".equalsIgnoreCase(str1))
            return getX448PrivateKey(optional.get()); 
        } 
      } 
      throw new InvalidKeyException("cannot use XEC private key with unknown algorithm");
    } 
    throw new InvalidKeyException("cannot identify XDH private key");
  }
  
  private AsymmetricKeyParameter getLwXDHKeyPublic(Key paramKey) throws InvalidKeyException {
    if (paramKey instanceof BCXDHPublicKey)
      return ((BCXDHPublicKey)paramKey).engineGetKeyParameters(); 
    if (paramKey instanceof XECPublicKey) {
      XECPublicKey xECPublicKey = (XECPublicKey)paramKey;
      BigInteger bigInteger = xECPublicKey.getU();
      if (bigInteger.signum() < 0)
        throw new InvalidKeyException("cannot use XEC public key with negative U value"); 
      String str = xECPublicKey.getAlgorithm();
      if ("X25519".equalsIgnoreCase(str))
        return getX25519PublicKey(bigInteger); 
      if ("X448".equalsIgnoreCase(str))
        return getX448PublicKey(bigInteger); 
      if ("XDH".equalsIgnoreCase(str)) {
        AlgorithmParameterSpec algorithmParameterSpec = xECPublicKey.getParams();
        if (algorithmParameterSpec instanceof NamedParameterSpec) {
          NamedParameterSpec namedParameterSpec = (NamedParameterSpec)algorithmParameterSpec;
          String str1 = namedParameterSpec.getName();
          if ("X25519".equalsIgnoreCase(str1))
            return getX25519PublicKey(bigInteger); 
          if ("X448".equalsIgnoreCase(str1))
            return getX448PublicKey(bigInteger); 
        } 
      } 
      throw new InvalidKeyException("cannot use XEC public key with unknown algorithm");
    } 
    throw new InvalidKeyException("cannot identify XDH public key");
  }
  
  private static byte[] getPublicKeyData(int paramInt, BigInteger paramBigInteger) throws InvalidKeyException {
    try {
      return Arrays.reverseInPlace(BigIntegers.asUnsignedByteArray(paramInt, paramBigInteger));
    } catch (RuntimeException runtimeException) {
      throw new InvalidKeyException("cannot use XEC public key with invalid U value");
    } 
  }
  
  private static X25519PrivateKeyParameters getX25519PrivateKey(byte[] paramArrayOfbyte) throws InvalidKeyException {
    if (32 != paramArrayOfbyte.length)
      throw new InvalidKeyException("cannot use XEC private key (X25519) with scalar of incorrect length"); 
    return new X25519PrivateKeyParameters(paramArrayOfbyte, 0);
  }
  
  private static X25519PublicKeyParameters getX25519PublicKey(BigInteger paramBigInteger) throws InvalidKeyException {
    byte[] arrayOfByte = getPublicKeyData(32, paramBigInteger);
    return new X25519PublicKeyParameters(arrayOfByte, 0);
  }
  
  private static X448PrivateKeyParameters getX448PrivateKey(byte[] paramArrayOfbyte) throws InvalidKeyException {
    if (56 != paramArrayOfbyte.length)
      throw new InvalidKeyException("cannot use XEC private key (X448) with scalar of incorrect length"); 
    return new X448PrivateKeyParameters(paramArrayOfbyte, 0);
  }
  
  private static X448PublicKeyParameters getX448PublicKey(BigInteger paramBigInteger) throws InvalidKeyException {
    byte[] arrayOfByte = getPublicKeyData(56, paramBigInteger);
    return new X448PublicKeyParameters(arrayOfByte, 0);
  }
}
