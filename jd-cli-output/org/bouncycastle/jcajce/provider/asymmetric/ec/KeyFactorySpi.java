package org.bouncycastle.jcajce.provider.asymmetric.ec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

public class KeyFactorySpi extends BaseKeyFactorySpi implements AsymmetricKeyInfoConverter {
  String algorithm;
  
  ProviderConfiguration configuration;
  
  KeyFactorySpi(String paramString, ProviderConfiguration paramProviderConfiguration) {
    this.algorithm = paramString;
    this.configuration = paramProviderConfiguration;
  }
  
  protected Key engineTranslateKey(Key paramKey) throws InvalidKeyException {
    if (paramKey instanceof ECPublicKey)
      return new BCECPublicKey((ECPublicKey)paramKey, this.configuration); 
    if (paramKey instanceof ECPrivateKey)
      return new BCECPrivateKey((ECPrivateKey)paramKey, this.configuration); 
    throw new InvalidKeyException("key type unknown");
  }
  
  protected KeySpec engineGetKeySpec(Key paramKey, Class paramClass) throws InvalidKeySpecException {
    if ((paramClass.isAssignableFrom(KeySpec.class) || paramClass.isAssignableFrom(ECPublicKeySpec.class)) && paramKey instanceof ECPublicKey) {
      ECPublicKey eCPublicKey = (ECPublicKey)paramKey;
      if (eCPublicKey.getParams() != null)
        return new ECPublicKeySpec(eCPublicKey.getW(), eCPublicKey.getParams()); 
      ECParameterSpec eCParameterSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
      return new ECPublicKeySpec(eCPublicKey.getW(), EC5Util.convertSpec(EC5Util.convertCurve(eCParameterSpec.getCurve(), eCParameterSpec.getSeed()), eCParameterSpec));
    } 
    if ((paramClass.isAssignableFrom(KeySpec.class) || paramClass.isAssignableFrom(ECPrivateKeySpec.class)) && paramKey instanceof ECPrivateKey) {
      ECPrivateKey eCPrivateKey = (ECPrivateKey)paramKey;
      if (eCPrivateKey.getParams() != null)
        return new ECPrivateKeySpec(eCPrivateKey.getS(), eCPrivateKey.getParams()); 
      ECParameterSpec eCParameterSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
      return new ECPrivateKeySpec(eCPrivateKey.getS(), EC5Util.convertSpec(EC5Util.convertCurve(eCParameterSpec.getCurve(), eCParameterSpec.getSeed()), eCParameterSpec));
    } 
    if (paramClass.isAssignableFrom(ECPublicKeySpec.class) && paramKey instanceof ECPublicKey) {
      ECPublicKey eCPublicKey = (ECPublicKey)paramKey;
      if (eCPublicKey.getParams() != null)
        return new ECPublicKeySpec(EC5Util.convertPoint(eCPublicKey.getParams(), eCPublicKey.getW()), EC5Util.convertSpec(eCPublicKey.getParams())); 
      ECParameterSpec eCParameterSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
      return new ECPublicKeySpec(EC5Util.convertPoint(eCPublicKey.getParams(), eCPublicKey.getW()), eCParameterSpec);
    } 
    if (paramClass.isAssignableFrom(ECPrivateKeySpec.class) && paramKey instanceof ECPrivateKey) {
      ECPrivateKey eCPrivateKey = (ECPrivateKey)paramKey;
      if (eCPrivateKey.getParams() != null)
        return new ECPrivateKeySpec(eCPrivateKey.getS(), EC5Util.convertSpec(eCPrivateKey.getParams())); 
      ECParameterSpec eCParameterSpec = BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
      return new ECPrivateKeySpec(eCPrivateKey.getS(), eCParameterSpec);
    } 
    if (paramClass.isAssignableFrom(OpenSSHPublicKeySpec.class) && paramKey instanceof ECPublicKey) {
      if (paramKey instanceof BCECPublicKey) {
        BCECPublicKey bCECPublicKey = (BCECPublicKey)paramKey;
        ECParameterSpec eCParameterSpec = bCECPublicKey.getParameters();
        try {
          return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(new ECPublicKeyParameters(bCECPublicKey.getQ(), new ECDomainParameters(eCParameterSpec.getCurve(), eCParameterSpec.getG(), eCParameterSpec.getN(), eCParameterSpec.getH(), eCParameterSpec.getSeed()))));
        } catch (IOException iOException) {
          throw new IllegalArgumentException("unable to produce encoding: " + iOException.getMessage());
        } 
      } 
      throw new IllegalArgumentException("invalid key type: " + paramKey.getClass().getName());
    } 
    if (paramClass.isAssignableFrom(OpenSSHPrivateKeySpec.class) && paramKey instanceof ECPrivateKey) {
      if (paramKey instanceof BCECPrivateKey)
        try {
          return new OpenSSHPrivateKeySpec(PrivateKeyInfo.getInstance(paramKey.getEncoded()).parsePrivateKey().toASN1Primitive().getEncoded());
        } catch (IOException iOException) {
          throw new IllegalArgumentException("cannot encoded key: " + iOException.getMessage());
        }  
      throw new IllegalArgumentException("invalid key type: " + paramKey.getClass().getName());
    } 
    return super.engineGetKeySpec(paramKey, paramClass);
  }
  
  protected PrivateKey engineGeneratePrivate(KeySpec paramKeySpec) throws InvalidKeySpecException {
    if (paramKeySpec instanceof ECPrivateKeySpec)
      return new BCECPrivateKey(this.algorithm, (ECPrivateKeySpec)paramKeySpec, this.configuration); 
    if (paramKeySpec instanceof ECPrivateKeySpec)
      return new BCECPrivateKey(this.algorithm, (ECPrivateKeySpec)paramKeySpec, this.configuration); 
    if (paramKeySpec instanceof OpenSSHPrivateKeySpec) {
      ECPrivateKey eCPrivateKey = ECPrivateKey.getInstance(((OpenSSHPrivateKeySpec)paramKeySpec).getEncoded());
      try {
        return new BCECPrivateKey(this.algorithm, new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, eCPrivateKey.getParametersObject()), eCPrivateKey), this.configuration);
      } catch (IOException iOException) {
        throw new InvalidKeySpecException("bad encoding: " + iOException.getMessage());
      } 
    } 
    return super.engineGeneratePrivate(paramKeySpec);
  }
  
  protected PublicKey engineGeneratePublic(KeySpec paramKeySpec) throws InvalidKeySpecException {
    try {
      if (paramKeySpec instanceof ECPublicKeySpec)
        return new BCECPublicKey(this.algorithm, (ECPublicKeySpec)paramKeySpec, this.configuration); 
      if (paramKeySpec instanceof ECPublicKeySpec)
        return new BCECPublicKey(this.algorithm, (ECPublicKeySpec)paramKeySpec, this.configuration); 
      if (paramKeySpec instanceof OpenSSHPublicKeySpec) {
        AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)paramKeySpec).getEncoded());
        if (asymmetricKeyParameter instanceof ECPublicKeyParameters) {
          ECDomainParameters eCDomainParameters = ((ECPublicKeyParameters)asymmetricKeyParameter).getParameters();
          return engineGeneratePublic(new ECPublicKeySpec(((ECPublicKeyParameters)asymmetricKeyParameter).getQ(), new ECParameterSpec(eCDomainParameters.getCurve(), eCDomainParameters.getG(), eCDomainParameters.getN(), eCDomainParameters.getH(), eCDomainParameters.getSeed())));
        } 
        throw new IllegalArgumentException("openssh key is not ec public key");
      } 
    } catch (Exception exception) {
      throw new InvalidKeySpecException("invalid KeySpec: " + exception.getMessage(), exception);
    } 
    return super.engineGeneratePublic(paramKeySpec);
  }
  
  public PrivateKey generatePrivate(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramPrivateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
    if (aSN1ObjectIdentifier.equals(X9ObjectIdentifiers.id_ecPublicKey))
      return new BCECPrivateKey(this.algorithm, paramPrivateKeyInfo, this.configuration); 
    throw new IOException("algorithm identifier " + aSN1ObjectIdentifier + " in key not recognised");
  }
  
  public PublicKey generatePublic(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramSubjectPublicKeyInfo.getAlgorithm().getAlgorithm();
    if (aSN1ObjectIdentifier.equals(X9ObjectIdentifiers.id_ecPublicKey))
      return new BCECPublicKey(this.algorithm, paramSubjectPublicKeyInfo, this.configuration); 
    throw new IOException("algorithm identifier " + aSN1ObjectIdentifier + " in key not recognised");
  }
  
  public static class EC extends KeyFactorySpi {
    public EC() {
      super("EC", BouncyCastleProvider.CONFIGURATION);
    }
  }
  
  public static class ECDH extends KeyFactorySpi {
    public ECDH() {
      super("ECDH", BouncyCastleProvider.CONFIGURATION);
    }
  }
  
  public static class ECDHC extends KeyFactorySpi {
    public ECDHC() {
      super("ECDHC", BouncyCastleProvider.CONFIGURATION);
    }
  }
  
  public static class ECDSA extends KeyFactorySpi {
    public ECDSA() {
      super("ECDSA", BouncyCastleProvider.CONFIGURATION);
    }
  }
  
  public static class ECGOST3410 extends KeyFactorySpi {
    public ECGOST3410() {
      super("ECGOST3410", BouncyCastleProvider.CONFIGURATION);
    }
  }
  
  public static class ECGOST3410_2012 extends KeyFactorySpi {
    public ECGOST3410_2012() {
      super("ECGOST3410-2012", BouncyCastleProvider.CONFIGURATION);
    }
  }
  
  public static class ECMQV extends KeyFactorySpi {
    public ECMQV() {
      super("ECMQV", BouncyCastleProvider.CONFIGURATION);
    }
  }
}
