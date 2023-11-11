package org.bouncycastle.pqc.jcajce.provider.lms;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.lms.LMSContext;
import org.bouncycastle.pqc.crypto.lms.LMSContextBasedSigner;
import org.bouncycastle.pqc.crypto.lms.LMSContextBasedVerifier;

public class LMSSignatureSpi extends Signature {
  private Digest digest;
  
  private MessageSigner signer;
  
  private SecureRandom random;
  
  private LMSContextBasedSigner lmOtsSigner;
  
  private LMSContextBasedVerifier lmOtsVerifier;
  
  protected LMSSignatureSpi(String paramString) {
    super(paramString);
  }
  
  protected LMSSignatureSpi(String paramString, Digest paramDigest) {
    super(paramString);
    this.digest = paramDigest;
  }
  
  protected void engineInitVerify(PublicKey paramPublicKey) throws InvalidKeyException {
    if (paramPublicKey instanceof BCLMSPublicKey) {
      this.digest = new NullDigest();
      this.digest.reset();
      this.lmOtsVerifier = (LMSContextBasedVerifier)((BCLMSPublicKey)paramPublicKey).getKeyParams();
    } else {
      throw new InvalidKeyException("unknown public key passed to XMSS");
    } 
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    this.random = paramSecureRandom;
    engineInitSign(paramPrivateKey);
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey) throws InvalidKeyException {
    if (paramPrivateKey instanceof BCLMSPrivateKey) {
      this.lmOtsSigner = (LMSContextBasedSigner)((BCLMSPrivateKey)paramPrivateKey).getKeyParams();
      if (this.lmOtsSigner.getUsagesRemaining() == 0L)
        throw new InvalidKeyException("private key exhausted"); 
      this.digest = null;
    } else {
      throw new InvalidKeyException("unknown private key passed to LMS");
    } 
  }
  
  protected void engineUpdate(byte paramByte) throws SignatureException {
    if (this.digest == null)
      this.digest = getSigner(); 
    this.digest.update(paramByte);
  }
  
  protected void engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws SignatureException {
    if (this.digest == null)
      this.digest = getSigner(); 
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  private Digest getSigner() throws SignatureException {
    try {
      return this.lmOtsSigner.generateLMSContext();
    } catch (ExhaustedPrivateKeyException exhaustedPrivateKeyException) {
      throw new SignatureException(exhaustedPrivateKeyException.getMessage(), exhaustedPrivateKeyException);
    } 
  }
  
  protected byte[] engineSign() throws SignatureException {
    if (this.digest == null)
      this.digest = getSigner(); 
    try {
      byte[] arrayOfByte = this.lmOtsSigner.generateSignature((LMSContext)this.digest);
      this.digest = null;
      return arrayOfByte;
    } catch (Exception exception) {
      if (exception instanceof IllegalStateException)
        throw new SignatureException(exception.getMessage(), exception); 
      throw new SignatureException(exception.toString(), exception);
    } 
  }
  
  protected boolean engineVerify(byte[] paramArrayOfbyte) throws SignatureException {
    LMSContext lMSContext = this.lmOtsVerifier.generateLMSContext(paramArrayOfbyte);
    byte[] arrayOfByte = DigestUtil.getDigestResult(this.digest);
    lMSContext.update(arrayOfByte, 0, arrayOfByte.length);
    return this.lmOtsVerifier.verify(lMSContext);
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
  
  public static class generic extends LMSSignatureSpi {
    public generic() {
      super("LMS", new NullDigest());
    }
  }
}
