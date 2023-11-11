package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;

public class DSADigestSigner implements Signer {
  private final DSA dsa;
  
  private final Digest digest;
  
  private final DSAEncoding encoding;
  
  private boolean forSigning;
  
  public DSADigestSigner(DSA paramDSA, Digest paramDigest) {
    this.dsa = paramDSA;
    this.digest = paramDigest;
    this.encoding = StandardDSAEncoding.INSTANCE;
  }
  
  public DSADigestSigner(DSAExt paramDSAExt, Digest paramDigest, DSAEncoding paramDSAEncoding) {
    this.dsa = paramDSAExt;
    this.digest = paramDigest;
    this.encoding = paramDSAEncoding;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    AsymmetricKeyParameter asymmetricKeyParameter;
    this.forSigning = paramBoolean;
    if (paramCipherParameters instanceof ParametersWithRandom) {
      asymmetricKeyParameter = (AsymmetricKeyParameter)((ParametersWithRandom)paramCipherParameters).getParameters();
    } else {
      asymmetricKeyParameter = (AsymmetricKeyParameter)paramCipherParameters;
    } 
    if (paramBoolean && !asymmetricKeyParameter.isPrivate())
      throw new IllegalArgumentException("Signing Requires Private Key."); 
    if (!paramBoolean && asymmetricKeyParameter.isPrivate())
      throw new IllegalArgumentException("Verification Requires Public Key."); 
    reset();
    this.dsa.init(paramBoolean, paramCipherParameters);
  }
  
  public void update(byte paramByte) {
    this.digest.update(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public byte[] generateSignature() {
    if (!this.forSigning)
      throw new IllegalStateException("DSADigestSigner not initialised for signature generation."); 
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
    BigInteger[] arrayOfBigInteger = this.dsa.generateSignature(arrayOfByte);
    try {
      return this.encoding.encode(getOrder(), arrayOfBigInteger[0], arrayOfBigInteger[1]);
    } catch (Exception exception) {
      throw new IllegalStateException("unable to encode signature");
    } 
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte) {
    if (this.forSigning)
      throw new IllegalStateException("DSADigestSigner not initialised for verification"); 
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
    try {
      BigInteger[] arrayOfBigInteger = this.encoding.decode(getOrder(), paramArrayOfbyte);
      return this.dsa.verifySignature(arrayOfByte, arrayOfBigInteger[0], arrayOfBigInteger[1]);
    } catch (Exception exception) {
      return false;
    } 
  }
  
  public void reset() {
    this.digest.reset();
  }
  
  protected BigInteger getOrder() {
    return (this.dsa instanceof DSAExt) ? ((DSAExt)this.dsa).getOrder() : null;
  }
}
