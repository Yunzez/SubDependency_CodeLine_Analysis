package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

public class SM2Engine {
  private final Digest digest;
  
  private final Mode mode;
  
  private boolean forEncryption;
  
  private ECKeyParameters ecKey;
  
  private ECDomainParameters ecParams;
  
  private int curveLength;
  
  private SecureRandom random;
  
  public SM2Engine() {
    this(new SM3Digest());
  }
  
  public SM2Engine(Mode paramMode) {
    this(new SM3Digest(), paramMode);
  }
  
  public SM2Engine(Digest paramDigest) {
    this(paramDigest, Mode.C1C2C3);
  }
  
  public SM2Engine(Digest paramDigest, Mode paramMode) {
    if (paramMode == null)
      throw new IllegalArgumentException("mode cannot be NULL"); 
    this.digest = paramDigest;
    this.mode = paramMode;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    this.forEncryption = paramBoolean;
    if (paramBoolean) {
      ParametersWithRandom parametersWithRandom = (ParametersWithRandom)paramCipherParameters;
      this.ecKey = (ECKeyParameters)parametersWithRandom.getParameters();
      this.ecParams = this.ecKey.getParameters();
      ECPoint eCPoint = ((ECPublicKeyParameters)this.ecKey).getQ().multiply(this.ecParams.getH());
      if (eCPoint.isInfinity())
        throw new IllegalArgumentException("invalid key: [h]Q at infinity"); 
      this.random = parametersWithRandom.getRandom();
    } else {
      this.ecKey = (ECKeyParameters)paramCipherParameters;
      this.ecParams = this.ecKey.getParameters();
    } 
    this.curveLength = (this.ecParams.getCurve().getFieldSize() + 7) / 8;
  }
  
  public byte[] processBlock(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws InvalidCipherTextException {
    return this.forEncryption ? encrypt(paramArrayOfbyte, paramInt1, paramInt2) : decrypt(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int getOutputSize(int paramInt) {
    return 1 + 2 * this.curveLength + paramInt + this.digest.getDigestSize();
  }
  
  protected ECMultiplier createBasePointMultiplier() {
    return new FixedPointCombMultiplier();
  }
  
  private byte[] encrypt(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws InvalidCipherTextException {
    byte[] arrayOfByte2;
    ECPoint eCPoint;
    byte[] arrayOfByte1 = new byte[paramInt2];
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte1, 0, arrayOfByte1.length);
    ECMultiplier eCMultiplier = createBasePointMultiplier();
    do {
      BigInteger bigInteger = nextK();
      ECPoint eCPoint1 = eCMultiplier.multiply(this.ecParams.getG(), bigInteger).normalize();
      arrayOfByte2 = eCPoint1.getEncoded(false);
      eCPoint = ((ECPublicKeyParameters)this.ecKey).getQ().multiply(bigInteger).normalize();
      kdf(this.digest, eCPoint, arrayOfByte1);
    } while (notEncrypted(arrayOfByte1, paramArrayOfbyte, paramInt1));
    byte[] arrayOfByte3 = new byte[this.digest.getDigestSize()];
    addFieldElement(this.digest, eCPoint.getAffineXCoord());
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
    addFieldElement(this.digest, eCPoint.getAffineYCoord());
    this.digest.doFinal(arrayOfByte3, 0);
    switch (this.mode) {
      case C1C3C2:
        return Arrays.concatenate(arrayOfByte2, arrayOfByte3, arrayOfByte1);
    } 
    return Arrays.concatenate(arrayOfByte2, arrayOfByte1, arrayOfByte3);
  }
  
  private byte[] decrypt(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws InvalidCipherTextException {
    byte[] arrayOfByte1 = new byte[this.curveLength * 2 + 1];
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte1, 0, arrayOfByte1.length);
    ECPoint eCPoint1 = this.ecParams.getCurve().decodePoint(arrayOfByte1);
    ECPoint eCPoint2 = eCPoint1.multiply(this.ecParams.getH());
    if (eCPoint2.isInfinity())
      throw new InvalidCipherTextException("[h]C1 at infinity"); 
    eCPoint1 = eCPoint1.multiply(((ECPrivateKeyParameters)this.ecKey).getD()).normalize();
    int i = this.digest.getDigestSize();
    byte[] arrayOfByte2 = new byte[paramInt2 - arrayOfByte1.length - i];
    if (this.mode == Mode.C1C3C2) {
      System.arraycopy(paramArrayOfbyte, paramInt1 + arrayOfByte1.length + i, arrayOfByte2, 0, arrayOfByte2.length);
    } else {
      System.arraycopy(paramArrayOfbyte, paramInt1 + arrayOfByte1.length, arrayOfByte2, 0, arrayOfByte2.length);
    } 
    kdf(this.digest, eCPoint1, arrayOfByte2);
    byte[] arrayOfByte3 = new byte[this.digest.getDigestSize()];
    addFieldElement(this.digest, eCPoint1.getAffineXCoord());
    this.digest.update(arrayOfByte2, 0, arrayOfByte2.length);
    addFieldElement(this.digest, eCPoint1.getAffineYCoord());
    this.digest.doFinal(arrayOfByte3, 0);
    int j = 0;
    if (this.mode == Mode.C1C3C2) {
      for (byte b = 0; b != arrayOfByte3.length; b++)
        j |= arrayOfByte3[b] ^ paramArrayOfbyte[paramInt1 + arrayOfByte1.length + b]; 
    } else {
      for (byte b = 0; b != arrayOfByte3.length; b++)
        j |= arrayOfByte3[b] ^ paramArrayOfbyte[paramInt1 + arrayOfByte1.length + arrayOfByte2.length + b]; 
    } 
    Arrays.fill(arrayOfByte1, (byte)0);
    Arrays.fill(arrayOfByte3, (byte)0);
    if (j != 0) {
      Arrays.fill(arrayOfByte2, (byte)0);
      throw new InvalidCipherTextException("invalid cipher text");
    } 
    return arrayOfByte2;
  }
  
  private boolean notEncrypted(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    for (byte b = 0; b != paramArrayOfbyte1.length; b++) {
      if (paramArrayOfbyte1[b] != paramArrayOfbyte2[paramInt + b])
        return false; 
    } 
    return true;
  }
  
  private void kdf(Digest paramDigest, ECPoint paramECPoint, byte[] paramArrayOfbyte) {
    int i = paramDigest.getDigestSize();
    byte[] arrayOfByte = new byte[Math.max(4, i)];
    int j = 0;
    Memoable memoable1 = null;
    Memoable memoable2 = null;
    if (paramDigest instanceof Memoable) {
      addFieldElement(paramDigest, paramECPoint.getAffineXCoord());
      addFieldElement(paramDigest, paramECPoint.getAffineYCoord());
      memoable1 = (Memoable)paramDigest;
      memoable2 = memoable1.copy();
    } 
    byte b = 0;
    while (j < paramArrayOfbyte.length) {
      if (memoable1 != null) {
        memoable1.reset(memoable2);
      } else {
        addFieldElement(paramDigest, paramECPoint.getAffineXCoord());
        addFieldElement(paramDigest, paramECPoint.getAffineYCoord());
      } 
      Pack.intToBigEndian(++b, arrayOfByte, 0);
      paramDigest.update(arrayOfByte, 0, 4);
      paramDigest.doFinal(arrayOfByte, 0);
      int k = Math.min(i, paramArrayOfbyte.length - j);
      xor(paramArrayOfbyte, arrayOfByte, j, k);
      j += k;
    } 
  }
  
  private void xor(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2) {
    for (int i = 0; i != paramInt2; i++)
      paramArrayOfbyte1[paramInt1 + i] = (byte)(paramArrayOfbyte1[paramInt1 + i] ^ paramArrayOfbyte2[i]); 
  }
  
  private BigInteger nextK() {
    int i = this.ecParams.getN().bitLength();
    while (true) {
      BigInteger bigInteger = BigIntegers.createRandomBigInteger(i, this.random);
      if (!bigInteger.equals(BigIntegers.ZERO) && bigInteger.compareTo(this.ecParams.getN()) < 0)
        return bigInteger; 
    } 
  }
  
  private void addFieldElement(Digest paramDigest, ECFieldElement paramECFieldElement) {
    byte[] arrayOfByte = BigIntegers.asUnsignedByteArray(this.curveLength, paramECFieldElement.toBigInteger());
    paramDigest.update(arrayOfByte, 0, arrayOfByte.length);
  }
  
  public enum Mode {
    C1C2C3, C1C3C2;
  }
}
