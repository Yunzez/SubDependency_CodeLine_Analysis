package org.bouncycastle.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.crypto.util.PBKDFConfig;

public class BCFKSLoadStoreParameter extends BCLoadStoreParameter {
  private final PBKDFConfig storeConfig;
  
  private final EncryptionAlgorithm encAlg;
  
  private final MacAlgorithm macAlg;
  
  private final SignatureAlgorithm sigAlg;
  
  private final Key sigKey;
  
  private final X509Certificate[] certificates;
  
  private final CertChainValidator validator;
  
  private BCFKSLoadStoreParameter(Builder paramBuilder) {
    super(paramBuilder.in, paramBuilder.out, paramBuilder.protectionParameter);
    this.storeConfig = paramBuilder.storeConfig;
    this.encAlg = paramBuilder.encAlg;
    this.macAlg = paramBuilder.macAlg;
    this.sigAlg = paramBuilder.sigAlg;
    this.sigKey = paramBuilder.sigKey;
    this.certificates = paramBuilder.certs;
    this.validator = paramBuilder.validator;
  }
  
  public PBKDFConfig getStorePBKDFConfig() {
    return this.storeConfig;
  }
  
  public EncryptionAlgorithm getStoreEncryptionAlgorithm() {
    return this.encAlg;
  }
  
  public MacAlgorithm getStoreMacAlgorithm() {
    return this.macAlg;
  }
  
  public SignatureAlgorithm getStoreSignatureAlgorithm() {
    return this.sigAlg;
  }
  
  public Key getStoreSignatureKey() {
    return this.sigKey;
  }
  
  public X509Certificate[] getStoreCertificates() {
    return this.certificates;
  }
  
  public CertChainValidator getCertChainValidator() {
    return this.validator;
  }
  
  public static class Builder {
    private final OutputStream out;
    
    private final InputStream in = null;
    
    private final KeyStore.ProtectionParameter protectionParameter;
    
    private final Key sigKey;
    
    private PBKDFConfig storeConfig = (new PBKDF2Config.Builder()).withIterationCount(16384).withSaltLength(64).withPRF(PBKDF2Config.PRF_SHA512).build();
    
    private BCFKSLoadStoreParameter.EncryptionAlgorithm encAlg = BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_CCM;
    
    private BCFKSLoadStoreParameter.MacAlgorithm macAlg = BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA512;
    
    private BCFKSLoadStoreParameter.SignatureAlgorithm sigAlg = BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withECDSA;
    
    private X509Certificate[] certs = null;
    
    private BCFKSLoadStoreParameter.CertChainValidator validator;
    
    public Builder() {
      this((OutputStream)null, (KeyStore.ProtectionParameter)null);
    }
    
    public Builder(OutputStream param1OutputStream, char[] param1ArrayOfchar) {
      this(param1OutputStream, new KeyStore.PasswordProtection(param1ArrayOfchar));
    }
    
    public Builder(OutputStream param1OutputStream, KeyStore.ProtectionParameter param1ProtectionParameter) {
      this.out = param1OutputStream;
      this.protectionParameter = param1ProtectionParameter;
      this.sigKey = null;
    }
    
    public Builder(OutputStream param1OutputStream, PrivateKey param1PrivateKey) {
      this.out = param1OutputStream;
      this.protectionParameter = null;
      this.sigKey = param1PrivateKey;
    }
    
    public Builder(InputStream param1InputStream, PublicKey param1PublicKey) {
      this.out = null;
      this.protectionParameter = null;
      this.sigKey = param1PublicKey;
    }
    
    public Builder(InputStream param1InputStream, BCFKSLoadStoreParameter.CertChainValidator param1CertChainValidator) {
      this.out = null;
      this.protectionParameter = null;
      this.validator = param1CertChainValidator;
      this.sigKey = null;
    }
    
    public Builder(InputStream param1InputStream, char[] param1ArrayOfchar) {
      this(param1InputStream, new KeyStore.PasswordProtection(param1ArrayOfchar));
    }
    
    public Builder(InputStream param1InputStream, KeyStore.ProtectionParameter param1ProtectionParameter) {
      this.out = null;
      this.protectionParameter = param1ProtectionParameter;
      this.sigKey = null;
    }
    
    public Builder withStorePBKDFConfig(PBKDFConfig param1PBKDFConfig) {
      this.storeConfig = param1PBKDFConfig;
      return this;
    }
    
    public Builder withStoreEncryptionAlgorithm(BCFKSLoadStoreParameter.EncryptionAlgorithm param1EncryptionAlgorithm) {
      this.encAlg = param1EncryptionAlgorithm;
      return this;
    }
    
    public Builder withStoreMacAlgorithm(BCFKSLoadStoreParameter.MacAlgorithm param1MacAlgorithm) {
      this.macAlg = param1MacAlgorithm;
      return this;
    }
    
    public Builder withCertificates(X509Certificate[] param1ArrayOfX509Certificate) {
      X509Certificate[] arrayOfX509Certificate = new X509Certificate[param1ArrayOfX509Certificate.length];
      System.arraycopy(param1ArrayOfX509Certificate, 0, arrayOfX509Certificate, 0, arrayOfX509Certificate.length);
      this.certs = arrayOfX509Certificate;
      return this;
    }
    
    public Builder withStoreSignatureAlgorithm(BCFKSLoadStoreParameter.SignatureAlgorithm param1SignatureAlgorithm) {
      this.sigAlg = param1SignatureAlgorithm;
      return this;
    }
    
    public BCFKSLoadStoreParameter build() {
      return new BCFKSLoadStoreParameter(this);
    }
  }
  
  public static interface CertChainValidator {
    boolean isValid(X509Certificate[] param1ArrayOfX509Certificate);
  }
  
  public enum EncryptionAlgorithm {
    AES256_CCM, AES256_KWP;
  }
  
  public enum MacAlgorithm {
    HmacSHA512, HmacSHA3_512;
  }
  
  public enum SignatureAlgorithm {
    SHA512withDSA, SHA3_512withDSA, SHA512withECDSA, SHA3_512withECDSA, SHA512withRSA, SHA3_512withRSA;
  }
}
