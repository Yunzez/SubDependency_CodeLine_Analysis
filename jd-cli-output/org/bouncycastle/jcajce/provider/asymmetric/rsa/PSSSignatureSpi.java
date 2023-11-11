package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;

public class PSSSignatureSpi extends SignatureSpi {
  private final JcaJceHelper helper = new BCJcaJceHelper();
  
  private AlgorithmParameters engineParams;
  
  private PSSParameterSpec paramSpec;
  
  private PSSParameterSpec originalSpec;
  
  private AsymmetricBlockCipher signer;
  
  private Digest contentDigest;
  
  private Digest mgfDigest;
  
  private int saltLength;
  
  private byte trailer;
  
  private boolean isRaw;
  
  private RSAKeyParameters key;
  
  private SecureRandom random;
  
  private PSSSigner pss;
  
  private boolean isInitState = true;
  
  private byte getTrailer(int paramInt) {
    if (paramInt == 1)
      return -68; 
    throw new IllegalArgumentException("unknown trailer field");
  }
  
  private void setupContentDigest() {
    if (this.isRaw) {
      this.contentDigest = new NullPssDigest(this.mgfDigest);
    } else {
      this.contentDigest = DigestFactory.getDigest(this.paramSpec.getDigestAlgorithm());
    } 
  }
  
  protected PSSSignatureSpi(AsymmetricBlockCipher paramAsymmetricBlockCipher, PSSParameterSpec paramPSSParameterSpec) {
    this(paramAsymmetricBlockCipher, paramPSSParameterSpec, false);
  }
  
  protected PSSSignatureSpi(AsymmetricBlockCipher paramAsymmetricBlockCipher, PSSParameterSpec paramPSSParameterSpec, boolean paramBoolean) {
    this.signer = paramAsymmetricBlockCipher;
    this.originalSpec = paramPSSParameterSpec;
    if (paramPSSParameterSpec == null) {
      this.paramSpec = PSSParameterSpec.DEFAULT;
    } else {
      this.paramSpec = paramPSSParameterSpec;
    } 
    if ("MGF1".equals(this.paramSpec.getMGFAlgorithm())) {
      this.mgfDigest = DigestFactory.getDigest(this.paramSpec.getDigestAlgorithm());
    } else {
      this.mgfDigest = DigestFactory.getDigest(this.paramSpec.getMGFAlgorithm());
    } 
    this.saltLength = this.paramSpec.getSaltLength();
    this.trailer = getTrailer(this.paramSpec.getTrailerField());
    this.isRaw = paramBoolean;
    setupContentDigest();
  }
  
  protected void engineInitVerify(PublicKey paramPublicKey) throws InvalidKeyException {
    if (!(paramPublicKey instanceof RSAPublicKey))
      throw new InvalidKeyException("Supplied key is not a RSAPublicKey instance"); 
    this.key = RSAUtil.generatePublicKeyParameter((RSAPublicKey)paramPublicKey);
    this.pss = new PSSSigner(this.signer, this.contentDigest, this.mgfDigest, this.saltLength, this.trailer);
    this.pss.init(false, this.key);
    this.isInitState = true;
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    this.random = paramSecureRandom;
    engineInitSign(paramPrivateKey);
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey) throws InvalidKeyException {
    if (!(paramPrivateKey instanceof RSAPrivateKey))
      throw new InvalidKeyException("Supplied key is not a RSAPrivateKey instance"); 
    this.key = RSAUtil.generatePrivateKeyParameter((RSAPrivateKey)paramPrivateKey);
    this.pss = new PSSSigner(this.signer, this.contentDigest, this.mgfDigest, this.saltLength, this.trailer);
    if (this.random != null) {
      this.pss.init(true, new ParametersWithRandom(this.key, this.random));
    } else {
      this.pss.init(true, this.key);
    } 
    this.isInitState = true;
  }
  
  protected void engineUpdate(byte paramByte) throws SignatureException {
    this.pss.update(paramByte);
    this.isInitState = false;
  }
  
  protected void engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws SignatureException {
    this.pss.update(paramArrayOfbyte, paramInt1, paramInt2);
    this.isInitState = false;
  }
  
  protected byte[] engineSign() throws SignatureException {
    this.isInitState = true;
    try {
      return this.pss.generateSignature();
    } catch (CryptoException cryptoException) {
      throw new SignatureException(cryptoException.getMessage());
    } 
  }
  
  protected boolean engineVerify(byte[] paramArrayOfbyte) throws SignatureException {
    this.isInitState = true;
    return this.pss.verifySignature(paramArrayOfbyte);
  }
  
  protected void engineSetParameter(AlgorithmParameterSpec paramAlgorithmParameterSpec) throws InvalidAlgorithmParameterException {
    if (paramAlgorithmParameterSpec == null)
      if (this.originalSpec != null) {
        paramAlgorithmParameterSpec = this.originalSpec;
      } else {
        return;
      }  
    if (!this.isInitState)
      throw new ProviderException("cannot call setParameter in the middle of update"); 
    if (paramAlgorithmParameterSpec instanceof PSSParameterSpec) {
      Digest digest;
      PSSParameterSpec pSSParameterSpec = (PSSParameterSpec)paramAlgorithmParameterSpec;
      if (this.originalSpec != null && !DigestFactory.isSameDigest(this.originalSpec.getDigestAlgorithm(), pSSParameterSpec.getDigestAlgorithm()))
        throw new InvalidAlgorithmParameterException("parameter must be using " + this.originalSpec.getDigestAlgorithm()); 
      if (pSSParameterSpec.getMGFAlgorithm().equalsIgnoreCase("MGF1") || pSSParameterSpec.getMGFAlgorithm().equals(PKCSObjectIdentifiers.id_mgf1.getId())) {
        if (!(pSSParameterSpec.getMGFParameters() instanceof MGF1ParameterSpec))
          throw new InvalidAlgorithmParameterException("unknown MGF parameters"); 
        MGF1ParameterSpec mGF1ParameterSpec = (MGF1ParameterSpec)pSSParameterSpec.getMGFParameters();
        if (!DigestFactory.isSameDigest(mGF1ParameterSpec.getDigestAlgorithm(), pSSParameterSpec.getDigestAlgorithm()))
          throw new InvalidAlgorithmParameterException("digest algorithm for MGF should be the same as for PSS parameters."); 
        digest = DigestFactory.getDigest(mGF1ParameterSpec.getDigestAlgorithm());
      } else if (pSSParameterSpec.getMGFAlgorithm().equals("SHAKE128") || pSSParameterSpec.getMGFAlgorithm().equals("SHAKE256")) {
        digest = DigestFactory.getDigest(pSSParameterSpec.getMGFAlgorithm());
      } else {
        throw new InvalidAlgorithmParameterException("unknown mask generation function specified");
      } 
      if (digest == null)
        throw new InvalidAlgorithmParameterException("no match on MGF algorithm: " + pSSParameterSpec.getMGFAlgorithm()); 
      this.engineParams = null;
      this.paramSpec = pSSParameterSpec;
      this.mgfDigest = digest;
      this.saltLength = this.paramSpec.getSaltLength();
      this.trailer = getTrailer(this.paramSpec.getTrailerField());
      setupContentDigest();
      if (this.key != null) {
        this.pss = new PSSSigner(this.signer, this.contentDigest, digest, this.saltLength, this.trailer);
        if (this.key.isPrivate()) {
          this.pss.init(true, this.key);
        } else {
          this.pss.init(false, this.key);
        } 
      } 
    } else {
      throw new InvalidAlgorithmParameterException("Only PSSParameterSpec supported");
    } 
  }
  
  protected AlgorithmParameters engineGetParameters() {
    if (this.engineParams == null && this.paramSpec != null) {
      if (this.paramSpec.getDigestAlgorithm().equals(this.paramSpec.getMGFAlgorithm()) && this.paramSpec.getMGFParameters() == null)
        return null; 
      try {
        this.engineParams = this.helper.createAlgorithmParameters("PSS");
        this.engineParams.init(this.paramSpec);
      } catch (Exception exception) {
        throw new RuntimeException(exception.toString());
      } 
    } 
    return this.engineParams;
  }
  
  protected void engineSetParameter(String paramString, Object paramObject) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
  
  protected Object engineGetParameter(String paramString) {
    throw new UnsupportedOperationException("engineGetParameter unsupported");
  }
  
  private class NullPssDigest implements Digest {
    private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
    
    private Digest baseDigest;
    
    private boolean oddTime = true;
    
    public NullPssDigest(Digest param1Digest) {
      this.baseDigest = param1Digest;
    }
    
    public String getAlgorithmName() {
      return "NULL";
    }
    
    public int getDigestSize() {
      return this.baseDigest.getDigestSize();
    }
    
    public void update(byte param1Byte) {
      this.bOut.write(param1Byte);
    }
    
    public void update(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      this.bOut.write(param1ArrayOfbyte, param1Int1, param1Int2);
    }
    
    public int doFinal(byte[] param1ArrayOfbyte, int param1Int) {
      byte[] arrayOfByte = this.bOut.toByteArray();
      if (this.oddTime) {
        System.arraycopy(arrayOfByte, 0, param1ArrayOfbyte, param1Int, arrayOfByte.length);
      } else {
        this.baseDigest.update(arrayOfByte, 0, arrayOfByte.length);
        this.baseDigest.doFinal(param1ArrayOfbyte, param1Int);
      } 
      reset();
      this.oddTime = !this.oddTime;
      return arrayOfByte.length;
    }
    
    public void reset() {
      this.bOut.reset();
      this.baseDigest.reset();
    }
    
    public int getByteLength() {
      return 0;
    }
  }
  
  public static class PSSwithRSA extends PSSSignatureSpi {
    public PSSwithRSA() {
      super(new RSABlindedEngine(), null);
    }
  }
  
  public static class SHA1withRSA extends PSSSignatureSpi {
    public SHA1withRSA() {
      super(new RSABlindedEngine(), PSSParameterSpec.DEFAULT);
    }
  }
  
  public static class SHA1withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA1withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA1", "SHAKE128", null, 20, 1));
    }
  }
  
  public static class SHA1withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA1withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA1", "SHAKE256", null, 20, 1));
    }
  }
  
  public static class SHA224withRSA extends PSSSignatureSpi {
    public SHA224withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), 28, 1));
    }
  }
  
  public static class SHA224withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA224withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "SHAKE128", null, 28, 1));
    }
  }
  
  public static class SHA224withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA224withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-224", "SHAKE256", null, 28, 1));
    }
  }
  
  public static class SHA256withRSA extends PSSSignatureSpi {
    public SHA256withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
    }
  }
  
  public static class SHA256withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA256withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "SHAKE128", null, 32, 1));
    }
  }
  
  public static class SHA256withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA256withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-256", "SHAKE256", null, 32, 1));
    }
  }
  
  public static class SHA384withRSA extends PSSSignatureSpi {
    public SHA384withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
    }
  }
  
  public static class SHA384withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA384withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "SHAKE128", null, 48, 1));
    }
  }
  
  public static class SHA384withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA384withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-384", "SHAKE256", null, 48, 1));
    }
  }
  
  public static class SHA3_224withRSA extends PSSSignatureSpi {
    public SHA3_224withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-224", "MGF1", new MGF1ParameterSpec("SHA3-224"), 28, 1));
    }
  }
  
  public static class SHA3_224withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA3_224withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-224", "SHAKE128", null, 28, 1));
    }
  }
  
  public static class SHA3_224withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA3_224withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-224", "SHAKE256", null, 28, 1));
    }
  }
  
  public static class SHA3_256withRSA extends PSSSignatureSpi {
    public SHA3_256withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-256", "MGF1", new MGF1ParameterSpec("SHA3-256"), 32, 1));
    }
  }
  
  public static class SHA3_256withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA3_256withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-256", "SHAKE128", null, 32, 1));
    }
  }
  
  public static class SHA3_256withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA3_256withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-256", "SHAKE256", null, 32, 1));
    }
  }
  
  public static class SHA3_384withRSA extends PSSSignatureSpi {
    public SHA3_384withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-384", "MGF1", new MGF1ParameterSpec("SHA3-384"), 48, 1));
    }
  }
  
  public static class SHA3_384withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA3_384withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-384", "SHAKE128", null, 48, 1));
    }
  }
  
  public static class SHA3_384withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA3_384withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-384", "SHAKE256", null, 48, 1));
    }
  }
  
  public static class SHA3_512withRSA extends PSSSignatureSpi {
    public SHA3_512withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-512", "MGF1", new MGF1ParameterSpec("SHA3-512"), 64, 1));
    }
  }
  
  public static class SHA3_512withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA3_512withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-512", "SHAKE128", null, 64, 1));
    }
  }
  
  public static class SHA3_512withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA3_512withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA3-512", "SHAKE256", null, 64, 1));
    }
  }
  
  public static class SHA512_224withRSA extends PSSSignatureSpi {
    public SHA512_224withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(224)", "MGF1", new MGF1ParameterSpec("SHA-512(224)"), 28, 1));
    }
  }
  
  public static class SHA512_224withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA512_224withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(224)", "SHAKE128", null, 28, 1));
    }
  }
  
  public static class SHA512_224withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA512_224withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(224)", "SHAKE256", null, 28, 1));
    }
  }
  
  public static class SHA512_256withRSA extends PSSSignatureSpi {
    public SHA512_256withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(256)", "MGF1", new MGF1ParameterSpec("SHA-512(256)"), 32, 1));
    }
  }
  
  public static class SHA512_256withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA512_256withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(256)", "SHAKE128", null, 32, 1));
    }
  }
  
  public static class SHA512_256withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA512_256withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512(256)", "SHAKE256", null, 32, 1));
    }
  }
  
  public static class SHA512withRSA extends PSSSignatureSpi {
    public SHA512withRSA() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1));
    }
  }
  
  public static class SHA512withRSAandSHAKE128 extends PSSSignatureSpi {
    public SHA512withRSAandSHAKE128() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "SHAKE128", null, 64, 1));
    }
  }
  
  public static class SHA512withRSAandSHAKE256 extends PSSSignatureSpi {
    public SHA512withRSAandSHAKE256() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHA-512", "SHAKE256", null, 64, 1));
    }
  }
  
  public static class SHAKE128WithRSAPSS extends PSSSignatureSpi {
    public SHAKE128WithRSAPSS() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHAKE128", "SHAKE128", null, 32, 1));
    }
  }
  
  public static class SHAKE256WithRSAPSS extends PSSSignatureSpi {
    public SHAKE256WithRSAPSS() {
      super(new RSABlindedEngine(), new PSSParameterSpec("SHAKE256", "SHAKE256", null, 64, 1));
    }
  }
  
  public static class nonePSS extends PSSSignatureSpi {
    public nonePSS() {
      super(new RSABlindedEngine(), null, true);
    }
  }
}
