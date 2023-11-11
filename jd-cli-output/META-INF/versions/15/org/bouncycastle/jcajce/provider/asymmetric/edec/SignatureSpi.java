package META-INF.versions.15.org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class SignatureSpi extends SignatureSpi {
  private static final byte[] EMPTY_CONTEXT = new byte[0];
  
  private final String algorithm;
  
  private Signer signer;
  
  SignatureSpi(String paramString) {
    this.algorithm = paramString;
  }
  
  protected void engineInitVerify(PublicKey paramPublicKey) throws InvalidKeyException {
    AsymmetricKeyParameter asymmetricKeyParameter = getLwEdDSAKeyPublic(paramPublicKey);
    if (asymmetricKeyParameter instanceof Ed25519PublicKeyParameters) {
      this.signer = getSigner("Ed25519");
    } else if (asymmetricKeyParameter instanceof Ed448PublicKeyParameters) {
      this.signer = getSigner("Ed448");
    } else {
      throw new IllegalStateException("unsupported public key type");
    } 
    this.signer.init(false, asymmetricKeyParameter);
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey) throws InvalidKeyException {
    AsymmetricKeyParameter asymmetricKeyParameter = getLwEdDSAKeyPrivate(paramPrivateKey);
    if (asymmetricKeyParameter instanceof Ed25519PrivateKeyParameters) {
      this.signer = getSigner("Ed25519");
    } else if (asymmetricKeyParameter instanceof Ed448PrivateKeyParameters) {
      this.signer = getSigner("Ed448");
    } else {
      throw new IllegalStateException("unsupported private key type");
    } 
    this.signer.init(true, asymmetricKeyParameter);
  }
  
  private static Ed25519PrivateKeyParameters getEd25519PrivateKey(byte[] paramArrayOfbyte) throws InvalidKeyException {
    if (32 != paramArrayOfbyte.length)
      throw new InvalidKeyException("cannot use EdEC private key (Ed25519) with bytes of incorrect length"); 
    return new Ed25519PrivateKeyParameters(paramArrayOfbyte, 0);
  }
  
  private static Ed25519PublicKeyParameters getEd25519PublicKey(EdECPoint paramEdECPoint) throws InvalidKeyException {
    byte[] arrayOfByte = getPublicKeyData(32, paramEdECPoint);
    return new Ed25519PublicKeyParameters(arrayOfByte, 0);
  }
  
  private static Ed448PrivateKeyParameters getEd448PrivateKey(byte[] paramArrayOfbyte) throws InvalidKeyException {
    if (57 != paramArrayOfbyte.length)
      throw new InvalidKeyException("cannot use EdEC private key (Ed448) with bytes of incorrect length"); 
    return new Ed448PrivateKeyParameters(paramArrayOfbyte, 0);
  }
  
  private static Ed448PublicKeyParameters getEd448PublicKey(EdECPoint paramEdECPoint) throws InvalidKeyException {
    byte[] arrayOfByte = getPublicKeyData(57, paramEdECPoint);
    return new Ed448PublicKeyParameters(arrayOfByte, 0);
  }
  
  private static AsymmetricKeyParameter getLwEdDSAKeyPrivate(Key paramKey) throws InvalidKeyException {
    if (paramKey instanceof BCEdDSAPrivateKey)
      return ((BCEdDSAPrivateKey)paramKey).engineGetKeyParameters(); 
    if (paramKey instanceof EdECPrivateKey) {
      EdECPrivateKey edECPrivateKey = (EdECPrivateKey)paramKey;
      Optional<byte[]> optional = edECPrivateKey.getBytes();
      if (!optional.isPresent())
        throw new InvalidKeyException("cannot use EdEC private key without bytes"); 
      String str = edECPrivateKey.getAlgorithm();
      if ("Ed25519".equalsIgnoreCase(str))
        return getEd25519PrivateKey(optional.get()); 
      if ("Ed448".equalsIgnoreCase(str))
        return getEd448PrivateKey(optional.get()); 
      if ("EdDSA".equalsIgnoreCase(str)) {
        NamedParameterSpec namedParameterSpec = edECPrivateKey.getParams();
        if (namedParameterSpec instanceof NamedParameterSpec) {
          NamedParameterSpec namedParameterSpec1 = namedParameterSpec;
          String str1 = namedParameterSpec1.getName();
          if ("Ed25519".equalsIgnoreCase(str1))
            return getEd25519PrivateKey(optional.get()); 
          if ("Ed448".equalsIgnoreCase(str1))
            return getEd448PrivateKey(optional.get()); 
        } 
      } 
      throw new InvalidKeyException("cannot use EdEC private key with unknown algorithm");
    } 
    throw new InvalidKeyException("cannot identify EdDSA private key");
  }
  
  private static AsymmetricKeyParameter getLwEdDSAKeyPublic(Key paramKey) throws InvalidKeyException {
    if (paramKey instanceof BCEdDSAPublicKey)
      return ((BCEdDSAPublicKey)paramKey).engineGetKeyParameters(); 
    if (paramKey instanceof EdECPublicKey) {
      EdECPublicKey edECPublicKey = (EdECPublicKey)paramKey;
      EdECPoint edECPoint = edECPublicKey.getPoint();
      String str = edECPublicKey.getAlgorithm();
      if ("Ed25519".equalsIgnoreCase(str))
        return getEd25519PublicKey(edECPoint); 
      if ("Ed448".equalsIgnoreCase(str))
        return getEd448PublicKey(edECPoint); 
      if ("EdDSA".equalsIgnoreCase(str)) {
        NamedParameterSpec namedParameterSpec = edECPublicKey.getParams();
        if (namedParameterSpec instanceof NamedParameterSpec) {
          NamedParameterSpec namedParameterSpec1 = namedParameterSpec;
          String str1 = namedParameterSpec1.getName();
          if ("Ed25519".equalsIgnoreCase(str1))
            return getEd25519PublicKey(edECPoint); 
          if ("Ed448".equalsIgnoreCase(str1))
            return getEd448PublicKey(edECPoint); 
        } 
      } 
      throw new InvalidKeyException("cannot use EdEC public key with unknown algorithm");
    } 
    throw new InvalidKeyException("cannot identify EdDSA public key");
  }
  
  private static byte[] getPublicKeyData(int paramInt, EdECPoint paramEdECPoint) throws InvalidKeyException {
    BigInteger bigInteger = paramEdECPoint.getY();
    if (bigInteger.signum() < 0)
      throw new InvalidKeyException("cannot use EdEC public key with negative Y value"); 
    try {
      byte[] arrayOfByte = BigIntegers.asUnsignedByteArray(paramInt, bigInteger);
      if ((arrayOfByte[0] & 0x80) == 0) {
        if (paramEdECPoint.isXOdd())
          arrayOfByte[0] = (byte)(arrayOfByte[0] | 0x80); 
        return Arrays.reverseInPlace(arrayOfByte);
      } 
    } catch (RuntimeException runtimeException) {}
    throw new InvalidKeyException("cannot use EdEC public key with invalid Y value");
  }
  
  private Signer getSigner(String paramString) throws InvalidKeyException {
    if (this.algorithm != null && !paramString.equals(this.algorithm))
      throw new InvalidKeyException("inappropriate key for " + this.algorithm); 
    if (paramString.equals("Ed448"))
      return new Ed448Signer(EMPTY_CONTEXT); 
    return new Ed25519Signer();
  }
  
  protected void engineUpdate(byte paramByte) throws SignatureException {
    this.signer.update(paramByte);
  }
  
  protected void engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws SignatureException {
    this.signer.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  protected byte[] engineSign() throws SignatureException {
    try {
      return this.signer.generateSignature();
    } catch (CryptoException cryptoException) {
      throw new SignatureException(cryptoException.getMessage());
    } 
  }
  
  protected boolean engineVerify(byte[] paramArrayOfbyte) throws SignatureException {
    return this.signer.verifySignature(paramArrayOfbyte);
  }
  
  protected void engineSetParameter(String paramString, Object paramObject) throws InvalidParameterException {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
  
  protected Object engineGetParameter(String paramString) throws InvalidParameterException {
    throw new UnsupportedOperationException("engineGetParameter unsupported");
  }
  
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }
}
