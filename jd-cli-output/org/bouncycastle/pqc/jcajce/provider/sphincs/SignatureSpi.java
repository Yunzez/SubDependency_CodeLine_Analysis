package org.bouncycastle.pqc.jcajce.provider.sphincs;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCS256Signer;

public class SignatureSpi extends SignatureSpi {
  private final ASN1ObjectIdentifier treeDigest;
  
  private Digest digest;
  
  private SPHINCS256Signer signer;
  
  private SecureRandom random;
  
  protected SignatureSpi(Digest paramDigest, ASN1ObjectIdentifier paramASN1ObjectIdentifier, SPHINCS256Signer paramSPHINCS256Signer) {
    this.digest = paramDigest;
    this.treeDigest = paramASN1ObjectIdentifier;
    this.signer = paramSPHINCS256Signer;
  }
  
  protected void engineInitVerify(PublicKey paramPublicKey) throws InvalidKeyException {
    if (paramPublicKey instanceof BCSphincs256PublicKey) {
      BCSphincs256PublicKey bCSphincs256PublicKey = (BCSphincs256PublicKey)paramPublicKey;
      if (!this.treeDigest.equals(bCSphincs256PublicKey.getTreeDigest()))
        throw new InvalidKeyException("SPHINCS-256 signature for tree digest: " + bCSphincs256PublicKey.getTreeDigest()); 
      CipherParameters cipherParameters = bCSphincs256PublicKey.getKeyParams();
      this.digest.reset();
      this.signer.init(false, cipherParameters);
    } else {
      throw new InvalidKeyException("unknown public key passed to SPHINCS-256");
    } 
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey, SecureRandom paramSecureRandom) throws InvalidKeyException {
    this.random = paramSecureRandom;
    engineInitSign(paramPrivateKey);
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey) throws InvalidKeyException {
    if (paramPrivateKey instanceof BCSphincs256PrivateKey) {
      BCSphincs256PrivateKey bCSphincs256PrivateKey = (BCSphincs256PrivateKey)paramPrivateKey;
      if (!this.treeDigest.equals(bCSphincs256PrivateKey.getTreeDigest()))
        throw new InvalidKeyException("SPHINCS-256 signature for tree digest: " + bCSphincs256PrivateKey.getTreeDigest()); 
      CipherParameters cipherParameters = bCSphincs256PrivateKey.getKeyParams();
      this.digest.reset();
      this.signer.init(true, cipherParameters);
    } else {
      throw new InvalidKeyException("unknown private key passed to SPHINCS-256");
    } 
  }
  
  protected void engineUpdate(byte paramByte) throws SignatureException {
    this.digest.update(paramByte);
  }
  
  protected void engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws SignatureException {
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  protected byte[] engineSign() throws SignatureException {
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
    try {
      return this.signer.generateSignature(arrayOfByte);
    } catch (Exception exception) {
      throw new SignatureException(exception.toString());
    } 
  }
  
  protected boolean engineVerify(byte[] paramArrayOfbyte) throws SignatureException {
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
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
  
  public static class withSha3_512 extends SignatureSpi {
    public withSha3_512() {
      super(new SHA3Digest(512), NISTObjectIdentifiers.id_sha3_256, new SPHINCS256Signer(new SHA3Digest(256), new SHA3Digest(512)));
    }
  }
  
  public static class withSha512 extends SignatureSpi {
    public withSha512() {
      super(new SHA512Digest(), NISTObjectIdentifiers.id_sha512_256, new SPHINCS256Signer(new SHA512tDigest(256), new SHA512Digest()));
    }
  }
}
