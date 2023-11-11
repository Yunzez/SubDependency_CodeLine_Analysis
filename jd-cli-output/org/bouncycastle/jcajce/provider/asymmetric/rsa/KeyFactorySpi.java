package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.ExtendedInvalidKeySpecException;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;

public class KeyFactorySpi extends BaseKeyFactorySpi {
  protected KeySpec engineGetKeySpec(Key paramKey, Class paramClass) throws InvalidKeySpecException {
    if ((paramClass.isAssignableFrom(KeySpec.class) || paramClass.isAssignableFrom(RSAPublicKeySpec.class)) && paramKey instanceof RSAPublicKey) {
      RSAPublicKey rSAPublicKey = (RSAPublicKey)paramKey;
      return new RSAPublicKeySpec(rSAPublicKey.getModulus(), rSAPublicKey.getPublicExponent());
    } 
    if ((paramClass.isAssignableFrom(KeySpec.class) || paramClass.isAssignableFrom(RSAPrivateCrtKeySpec.class)) && paramKey instanceof RSAPrivateCrtKey) {
      RSAPrivateCrtKey rSAPrivateCrtKey = (RSAPrivateCrtKey)paramKey;
      return new RSAPrivateCrtKeySpec(rSAPrivateCrtKey.getModulus(), rSAPrivateCrtKey.getPublicExponent(), rSAPrivateCrtKey.getPrivateExponent(), rSAPrivateCrtKey.getPrimeP(), rSAPrivateCrtKey.getPrimeQ(), rSAPrivateCrtKey.getPrimeExponentP(), rSAPrivateCrtKey.getPrimeExponentQ(), rSAPrivateCrtKey.getCrtCoefficient());
    } 
    if ((paramClass.isAssignableFrom(KeySpec.class) || paramClass.isAssignableFrom(RSAPrivateKeySpec.class)) && paramKey instanceof RSAPrivateKey) {
      RSAPrivateKey rSAPrivateKey = (RSAPrivateKey)paramKey;
      return new RSAPrivateKeySpec(rSAPrivateKey.getModulus(), rSAPrivateKey.getPrivateExponent());
    } 
    if (paramClass.isAssignableFrom(OpenSSHPublicKeySpec.class) && paramKey instanceof RSAPublicKey)
      try {
        return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new RSAKeyParameters(false, ((RSAPublicKey)paramKey).getModulus(), ((RSAPublicKey)paramKey).getPublicExponent())));
      } catch (IOException iOException) {
        throw new IllegalArgumentException("unable to produce encoding: " + iOException.getMessage());
      }  
    if (paramClass.isAssignableFrom(OpenSSHPrivateKeySpec.class) && paramKey instanceof RSAPrivateCrtKey)
      try {
        return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new RSAPrivateCrtKeyParameters(((RSAPrivateCrtKey)paramKey).getModulus(), ((RSAPrivateCrtKey)paramKey).getPublicExponent(), ((RSAPrivateCrtKey)paramKey).getPrivateExponent(), ((RSAPrivateCrtKey)paramKey).getPrimeP(), ((RSAPrivateCrtKey)paramKey).getPrimeQ(), ((RSAPrivateCrtKey)paramKey).getPrimeExponentP(), ((RSAPrivateCrtKey)paramKey).getPrimeExponentQ(), ((RSAPrivateCrtKey)paramKey).getCrtCoefficient())));
      } catch (IOException iOException) {
        throw new IllegalArgumentException("unable to produce encoding: " + iOException.getMessage());
      }  
    return super.engineGetKeySpec(paramKey, paramClass);
  }
  
  protected Key engineTranslateKey(Key paramKey) throws InvalidKeyException {
    if (paramKey instanceof RSAPublicKey)
      return new BCRSAPublicKey((RSAPublicKey)paramKey); 
    if (paramKey instanceof RSAPrivateCrtKey)
      return new BCRSAPrivateCrtKey((RSAPrivateCrtKey)paramKey); 
    if (paramKey instanceof RSAPrivateKey)
      return new BCRSAPrivateKey((RSAPrivateKey)paramKey); 
    throw new InvalidKeyException("key type unknown");
  }
  
  protected PrivateKey engineGeneratePrivate(KeySpec paramKeySpec) throws InvalidKeySpecException {
    if (paramKeySpec instanceof PKCS8EncodedKeySpec)
      try {
        return generatePrivate(PrivateKeyInfo.getInstance(((PKCS8EncodedKeySpec)paramKeySpec).getEncoded()));
      } catch (Exception exception) {
        try {
          return new BCRSAPrivateCrtKey(RSAPrivateKey.getInstance(((PKCS8EncodedKeySpec)paramKeySpec).getEncoded()));
        } catch (Exception exception1) {
          throw new ExtendedInvalidKeySpecException("unable to process key spec: " + exception.toString(), exception);
        } 
      }  
    if (paramKeySpec instanceof RSAPrivateCrtKeySpec)
      return new BCRSAPrivateCrtKey((RSAPrivateCrtKeySpec)paramKeySpec); 
    if (paramKeySpec instanceof RSAPrivateKeySpec)
      return new BCRSAPrivateKey((RSAPrivateKeySpec)paramKeySpec); 
    if (paramKeySpec instanceof OpenSSHPrivateKeySpec) {
      AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)paramKeySpec).getEncoded());
      if (asymmetricKeyParameter instanceof RSAPrivateCrtKeyParameters)
        return new BCRSAPrivateCrtKey((RSAPrivateCrtKeyParameters)asymmetricKeyParameter); 
      throw new InvalidKeySpecException("open SSH public key is not RSA private key");
    } 
    throw new InvalidKeySpecException("unknown KeySpec type: " + paramKeySpec.getClass().getName());
  }
  
  protected PublicKey engineGeneratePublic(KeySpec paramKeySpec) throws InvalidKeySpecException {
    if (paramKeySpec instanceof RSAPublicKeySpec)
      return new BCRSAPublicKey((RSAPublicKeySpec)paramKeySpec); 
    if (paramKeySpec instanceof OpenSSHPublicKeySpec) {
      AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)paramKeySpec).getEncoded());
      if (asymmetricKeyParameter instanceof RSAKeyParameters)
        return new BCRSAPublicKey((RSAKeyParameters)asymmetricKeyParameter); 
      throw new InvalidKeySpecException("Open SSH public key is not RSA public key");
    } 
    return super.engineGeneratePublic(paramKeySpec);
  }
  
  public PrivateKey generatePrivate(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramPrivateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
    if (RSAUtil.isRsaOid(aSN1ObjectIdentifier)) {
      RSAPrivateKey rSAPrivateKey = RSAPrivateKey.getInstance(paramPrivateKeyInfo.parsePrivateKey());
      return (rSAPrivateKey.getCoefficient().intValue() == 0) ? new BCRSAPrivateKey(paramPrivateKeyInfo.getPrivateKeyAlgorithm(), rSAPrivateKey) : new BCRSAPrivateCrtKey(paramPrivateKeyInfo);
    } 
    throw new IOException("algorithm identifier " + aSN1ObjectIdentifier + " in key not recognised");
  }
  
  public PublicKey generatePublic(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramSubjectPublicKeyInfo.getAlgorithm().getAlgorithm();
    if (RSAUtil.isRsaOid(aSN1ObjectIdentifier))
      return new BCRSAPublicKey(paramSubjectPublicKeyInfo); 
    throw new IOException("algorithm identifier " + aSN1ObjectIdentifier + " in key not recognised");
  }
}
