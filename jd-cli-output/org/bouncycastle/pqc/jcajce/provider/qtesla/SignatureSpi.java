package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASigner;

public class SignatureSpi extends Signature {
  private Digest digest;
  
  private QTESLASigner signer;
  
  private SecureRandom random;
  
  protected SignatureSpi(String paramString) {
    super(paramString);
  }
  
  protected SignatureSpi(String paramString, Digest paramDigest, QTESLASigner paramQTESLASigner) {
    super(paramString);
    this.digest = paramDigest;
    this.signer = paramQTESLASigner;
  }
  
  protected void engineInitVerify(PublicKey paramPublicKey) throws InvalidKeyException {
    if (paramPublicKey instanceof BCqTESLAPublicKey) {
      CipherParameters cipherParameters = ((BCqTESLAPublicKey)paramPublicKey).getKeyParams();
      this.digest.reset();
      this.signer.init(false, cipherParameters);
    } else {
      throw new InvalidKeyException("unknown public key passed to qTESLA");
    } 
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    this.random = paramSecureRandom;
    engineInitSign(paramPrivateKey);
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey) throws InvalidKeyException {
    if (paramPrivateKey instanceof BCqTESLAPrivateKey) {
      CipherParameters cipherParameters = ((BCqTESLAPrivateKey)paramPrivateKey).getKeyParams();
      if (this.random != null)
        cipherParameters = new ParametersWithRandom(cipherParameters, this.random); 
      this.signer.init(true, cipherParameters);
    } else {
      throw new InvalidKeyException("unknown private key passed to qTESLA");
    } 
  }
  
  protected void engineUpdate(byte paramByte) throws SignatureException {
    this.digest.update(paramByte);
  }
  
  protected void engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws SignatureException {
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  protected byte[] engineSign() throws SignatureException {
    try {
      byte[] arrayOfByte = DigestUtil.getDigestResult(this.digest);
      return this.signer.generateSignature(arrayOfByte);
    } catch (Exception exception) {
      if (exception instanceof IllegalStateException)
        throw new SignatureException(exception.getMessage()); 
      throw new SignatureException(exception.toString());
    } 
  }
  
  protected boolean engineVerify(byte[] paramArrayOfbyte) throws SignatureException {
    byte[] arrayOfByte = DigestUtil.getDigestResult(this.digest);
    return this.signer.verifySignature(arrayOfByte, paramArrayOfbyte);
  }
  
  protected void engineSetParameter(AlgorithmParameterSpec paramAlgorithmParameterSpec) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
  
  protected void engineSetParameter(String paramString, Object paramObject) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
  
  protected Object engineGetParameter(String paramString) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
  
  public static class PI extends SignatureSpi {
    public PI() {
      super(QTESLASecurityCategory.getName(5), new NullDigest(), new QTESLASigner());
    }
  }
  
  public static class PIII extends SignatureSpi {
    public PIII() {
      super(QTESLASecurityCategory.getName(6), new NullDigest(), new QTESLASigner());
    }
  }
  
  public static class qTESLA extends SignatureSpi {
    public qTESLA() {
      super("qTESLA", new NullDigest(), new QTESLASigner());
    }
  }
}
