package org.bouncycastle.crypto.signers;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.Arrays;

public class PSSSigner implements Signer {
  public static final byte TRAILER_IMPLICIT = -68;
  
  private Digest contentDigest;
  
  private Digest mgfDigest;
  
  private AsymmetricBlockCipher cipher;
  
  private SecureRandom random;
  
  private int hLen;
  
  private int mgfhLen;
  
  private boolean sSet;
  
  private int sLen;
  
  private int emBits;
  
  private byte[] salt;
  
  private byte[] mDash;
  
  private byte[] block;
  
  private byte trailer;
  
  public PSSSigner(AsymmetricBlockCipher paramAsymmetricBlockCipher, Digest paramDigest, int paramInt) {
    this(paramAsymmetricBlockCipher, paramDigest, paramInt, (byte)-68);
  }
  
  public PSSSigner(AsymmetricBlockCipher paramAsymmetricBlockCipher, Digest paramDigest1, Digest paramDigest2, int paramInt) {
    this(paramAsymmetricBlockCipher, paramDigest1, paramDigest2, paramInt, (byte)-68);
  }
  
  public PSSSigner(AsymmetricBlockCipher paramAsymmetricBlockCipher, Digest paramDigest, int paramInt, byte paramByte) {
    this(paramAsymmetricBlockCipher, paramDigest, paramDigest, paramInt, paramByte);
  }
  
  public PSSSigner(AsymmetricBlockCipher paramAsymmetricBlockCipher, Digest paramDigest1, Digest paramDigest2, int paramInt, byte paramByte) {
    this.cipher = paramAsymmetricBlockCipher;
    this.contentDigest = paramDigest1;
    this.mgfDigest = paramDigest2;
    this.hLen = paramDigest1.getDigestSize();
    this.mgfhLen = paramDigest2.getDigestSize();
    this.sSet = false;
    this.sLen = paramInt;
    this.salt = new byte[paramInt];
    this.mDash = new byte[8 + paramInt + this.hLen];
    this.trailer = paramByte;
  }
  
  public PSSSigner(AsymmetricBlockCipher paramAsymmetricBlockCipher, Digest paramDigest, byte[] paramArrayOfbyte) {
    this(paramAsymmetricBlockCipher, paramDigest, paramDigest, paramArrayOfbyte, (byte)-68);
  }
  
  public PSSSigner(AsymmetricBlockCipher paramAsymmetricBlockCipher, Digest paramDigest1, Digest paramDigest2, byte[] paramArrayOfbyte) {
    this(paramAsymmetricBlockCipher, paramDigest1, paramDigest2, paramArrayOfbyte, (byte)-68);
  }
  
  public PSSSigner(AsymmetricBlockCipher paramAsymmetricBlockCipher, Digest paramDigest1, Digest paramDigest2, byte[] paramArrayOfbyte, byte paramByte) {
    this.cipher = paramAsymmetricBlockCipher;
    this.contentDigest = paramDigest1;
    this.mgfDigest = paramDigest2;
    this.hLen = paramDigest1.getDigestSize();
    this.mgfhLen = paramDigest2.getDigestSize();
    this.sSet = true;
    this.sLen = paramArrayOfbyte.length;
    this.salt = paramArrayOfbyte;
    this.mDash = new byte[8 + this.sLen + this.hLen];
    this.trailer = paramByte;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    CipherParameters cipherParameters;
    RSAKeyParameters rSAKeyParameters;
    if (paramCipherParameters instanceof ParametersWithRandom) {
      ParametersWithRandom parametersWithRandom = (ParametersWithRandom)paramCipherParameters;
      cipherParameters = parametersWithRandom.getParameters();
      this.random = parametersWithRandom.getRandom();
    } else {
      cipherParameters = paramCipherParameters;
      if (paramBoolean)
        this.random = CryptoServicesRegistrar.getSecureRandom(); 
    } 
    if (cipherParameters instanceof RSABlindingParameters) {
      rSAKeyParameters = ((RSABlindingParameters)cipherParameters).getPublicKey();
      this.cipher.init(paramBoolean, paramCipherParameters);
    } else {
      rSAKeyParameters = (RSAKeyParameters)cipherParameters;
      this.cipher.init(paramBoolean, cipherParameters);
    } 
    this.emBits = rSAKeyParameters.getModulus().bitLength() - 1;
    if (this.emBits < 8 * this.hLen + 8 * this.sLen + 9)
      throw new IllegalArgumentException("key too small for specified hash and salt lengths"); 
    this.block = new byte[(this.emBits + 7) / 8];
    reset();
  }
  
  private void clearBlock(byte[] paramArrayOfbyte) {
    for (byte b = 0; b != paramArrayOfbyte.length; b++)
      paramArrayOfbyte[b] = 0; 
  }
  
  public void update(byte paramByte) {
    this.contentDigest.update(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.contentDigest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public void reset() {
    this.contentDigest.reset();
  }
  
  public byte[] generateSignature() throws CryptoException, DataLengthException {
    this.contentDigest.doFinal(this.mDash, this.mDash.length - this.hLen - this.sLen);
    if (this.sLen != 0) {
      if (!this.sSet)
        this.random.nextBytes(this.salt); 
      System.arraycopy(this.salt, 0, this.mDash, this.mDash.length - this.sLen, this.sLen);
    } 
    byte[] arrayOfByte1 = new byte[this.hLen];
    this.contentDigest.update(this.mDash, 0, this.mDash.length);
    this.contentDigest.doFinal(arrayOfByte1, 0);
    this.block[this.block.length - this.sLen - 1 - this.hLen - 1] = 1;
    System.arraycopy(this.salt, 0, this.block, this.block.length - this.sLen - this.hLen - 1, this.sLen);
    byte[] arrayOfByte2 = maskGenerator(arrayOfByte1, 0, arrayOfByte1.length, this.block.length - this.hLen - 1);
    int i;
    for (i = 0; i != arrayOfByte2.length; i++)
      this.block[i] = (byte)(this.block[i] ^ arrayOfByte2[i]); 
    System.arraycopy(arrayOfByte1, 0, this.block, this.block.length - this.hLen - 1, this.hLen);
    i = 255 >>> this.block.length * 8 - this.emBits;
    this.block[0] = (byte)(this.block[0] & i);
    this.block[this.block.length - 1] = this.trailer;
    byte[] arrayOfByte3 = this.cipher.processBlock(this.block, 0, this.block.length);
    clearBlock(this.block);
    return arrayOfByte3;
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte) {
    this.contentDigest.doFinal(this.mDash, this.mDash.length - this.hLen - this.sLen);
    try {
      byte[] arrayOfByte1 = this.cipher.processBlock(paramArrayOfbyte, 0, paramArrayOfbyte.length);
      Arrays.fill(this.block, 0, this.block.length - arrayOfByte1.length, (byte)0);
      System.arraycopy(arrayOfByte1, 0, this.block, this.block.length - arrayOfByte1.length, arrayOfByte1.length);
    } catch (Exception exception) {
      return false;
    } 
    int i = 255 >>> this.block.length * 8 - this.emBits;
    if ((this.block[0] & 0xFF) != (this.block[0] & i) || this.block[this.block.length - 1] != this.trailer) {
      clearBlock(this.block);
      return false;
    } 
    byte[] arrayOfByte = maskGenerator(this.block, this.block.length - this.hLen - 1, this.hLen, this.block.length - this.hLen - 1);
    int j;
    for (j = 0; j != arrayOfByte.length; j++)
      this.block[j] = (byte)(this.block[j] ^ arrayOfByte[j]); 
    this.block[0] = (byte)(this.block[0] & i);
    for (j = 0; j != this.block.length - this.hLen - this.sLen - 2; j++) {
      if (this.block[j] != 0) {
        clearBlock(this.block);
        return false;
      } 
    } 
    if (this.block[this.block.length - this.hLen - this.sLen - 2] != 1) {
      clearBlock(this.block);
      return false;
    } 
    if (this.sSet) {
      System.arraycopy(this.salt, 0, this.mDash, this.mDash.length - this.sLen, this.sLen);
    } else {
      System.arraycopy(this.block, this.block.length - this.sLen - this.hLen - 1, this.mDash, this.mDash.length - this.sLen, this.sLen);
    } 
    this.contentDigest.update(this.mDash, 0, this.mDash.length);
    this.contentDigest.doFinal(this.mDash, this.mDash.length - this.hLen);
    j = this.block.length - this.hLen - 1;
    for (int k = this.mDash.length - this.hLen; k != this.mDash.length; k++) {
      if ((this.block[j] ^ this.mDash[k]) != 0) {
        clearBlock(this.mDash);
        clearBlock(this.block);
        return false;
      } 
      j++;
    } 
    clearBlock(this.mDash);
    clearBlock(this.block);
    return true;
  }
  
  private void ItoOSP(int paramInt, byte[] paramArrayOfbyte) {
    paramArrayOfbyte[0] = (byte)(paramInt >>> 24);
    paramArrayOfbyte[1] = (byte)(paramInt >>> 16);
    paramArrayOfbyte[2] = (byte)(paramInt >>> 8);
    paramArrayOfbyte[3] = (byte)(paramInt >>> 0);
  }
  
  private byte[] maskGenerator(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3) {
    if (this.mgfDigest instanceof Xof) {
      byte[] arrayOfByte = new byte[paramInt3];
      this.mgfDigest.update(paramArrayOfbyte, paramInt1, paramInt2);
      ((Xof)this.mgfDigest).doFinal(arrayOfByte, 0, arrayOfByte.length);
      return arrayOfByte;
    } 
    return maskGeneratorFunction1(paramArrayOfbyte, paramInt1, paramInt2, paramInt3);
  }
  
  private byte[] maskGeneratorFunction1(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3) {
    byte[] arrayOfByte1 = new byte[paramInt3];
    byte[] arrayOfByte2 = new byte[this.mgfhLen];
    byte[] arrayOfByte3 = new byte[4];
    byte b = 0;
    this.mgfDigest.reset();
    while (b < paramInt3 / this.mgfhLen) {
      ItoOSP(b, arrayOfByte3);
      this.mgfDigest.update(paramArrayOfbyte, paramInt1, paramInt2);
      this.mgfDigest.update(arrayOfByte3, 0, arrayOfByte3.length);
      this.mgfDigest.doFinal(arrayOfByte2, 0);
      System.arraycopy(arrayOfByte2, 0, arrayOfByte1, b * this.mgfhLen, this.mgfhLen);
      b++;
    } 
    if (b * this.mgfhLen < paramInt3) {
      ItoOSP(b, arrayOfByte3);
      this.mgfDigest.update(paramArrayOfbyte, paramInt1, paramInt2);
      this.mgfDigest.update(arrayOfByte3, 0, arrayOfByte3.length);
      this.mgfDigest.doFinal(arrayOfByte2, 0);
      System.arraycopy(arrayOfByte2, 0, arrayOfByte1, b * this.mgfhLen, arrayOfByte1.length - b * this.mgfhLen);
    } 
    return arrayOfByte1;
  }
}
