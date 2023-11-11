package org.bouncycastle.crypto.signers;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.encoders.Hex;

public class SM2Signer implements Signer, ECConstants {
  private final DSAKCalculator kCalculator = new RandomDSAKCalculator();
  
  private final Digest digest;
  
  private final DSAEncoding encoding;
  
  private ECDomainParameters ecParams;
  
  private ECPoint pubPoint;
  
  private ECKeyParameters ecKey;
  
  private byte[] z;
  
  public SM2Signer() {
    this(StandardDSAEncoding.INSTANCE, new SM3Digest());
  }
  
  public SM2Signer(Digest paramDigest) {
    this(StandardDSAEncoding.INSTANCE, paramDigest);
  }
  
  public SM2Signer(DSAEncoding paramDSAEncoding) {
    this.encoding = paramDSAEncoding;
    this.digest = new SM3Digest();
  }
  
  public SM2Signer(DSAEncoding paramDSAEncoding, Digest paramDigest) {
    this.encoding = paramDSAEncoding;
    this.digest = paramDigest;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    CipherParameters cipherParameters;
    byte[] arrayOfByte;
    if (paramCipherParameters instanceof ParametersWithID) {
      cipherParameters = ((ParametersWithID)paramCipherParameters).getParameters();
      arrayOfByte = ((ParametersWithID)paramCipherParameters).getID();
      if (arrayOfByte.length >= 8192)
        throw new IllegalArgumentException("SM2 user ID must be less than 2^16 bits long"); 
    } else {
      cipherParameters = paramCipherParameters;
      arrayOfByte = Hex.decodeStrict("31323334353637383132333435363738");
    } 
    if (paramBoolean) {
      if (cipherParameters instanceof ParametersWithRandom) {
        ParametersWithRandom parametersWithRandom = (ParametersWithRandom)cipherParameters;
        this.ecKey = (ECKeyParameters)parametersWithRandom.getParameters();
        this.ecParams = this.ecKey.getParameters();
        this.kCalculator.init(this.ecParams.getN(), parametersWithRandom.getRandom());
      } else {
        this.ecKey = (ECKeyParameters)cipherParameters;
        this.ecParams = this.ecKey.getParameters();
        this.kCalculator.init(this.ecParams.getN(), CryptoServicesRegistrar.getSecureRandom());
      } 
      this.pubPoint = createBasePointMultiplier().multiply(this.ecParams.getG(), ((ECPrivateKeyParameters)this.ecKey).getD()).normalize();
    } else {
      this.ecKey = (ECKeyParameters)cipherParameters;
      this.ecParams = this.ecKey.getParameters();
      this.pubPoint = ((ECPublicKeyParameters)this.ecKey).getQ();
    } 
    this.z = getZ(arrayOfByte);
    this.digest.update(this.z, 0, this.z.length);
  }
  
  public void update(byte paramByte) {
    this.digest.update(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public boolean verifySignature(byte[] paramArrayOfbyte) {
    try {
      BigInteger[] arrayOfBigInteger = this.encoding.decode(this.ecParams.getN(), paramArrayOfbyte);
      return verifySignature(arrayOfBigInteger[0], arrayOfBigInteger[1]);
    } catch (Exception exception) {
      return false;
    } 
  }
  
  public void reset() {
    this.digest.reset();
    if (this.z != null)
      this.digest.update(this.z, 0, this.z.length); 
  }
  
  public byte[] generateSignature() throws CryptoException {
    // Byte code:
    //   0: aload_0
    //   1: invokespecial digestDoFinal : ()[B
    //   4: astore_1
    //   5: aload_0
    //   6: getfield ecParams : Lorg/bouncycastle/crypto/params/ECDomainParameters;
    //   9: invokevirtual getN : ()Ljava/math/BigInteger;
    //   12: astore_2
    //   13: aload_0
    //   14: aload_2
    //   15: aload_1
    //   16: invokevirtual calculateE : (Ljava/math/BigInteger;[B)Ljava/math/BigInteger;
    //   19: astore_3
    //   20: aload_0
    //   21: getfield ecKey : Lorg/bouncycastle/crypto/params/ECKeyParameters;
    //   24: checkcast org/bouncycastle/crypto/params/ECPrivateKeyParameters
    //   27: invokevirtual getD : ()Ljava/math/BigInteger;
    //   30: astore #4
    //   32: aload_0
    //   33: invokevirtual createBasePointMultiplier : ()Lorg/bouncycastle/math/ec/ECMultiplier;
    //   36: astore #7
    //   38: aload_0
    //   39: getfield kCalculator : Lorg/bouncycastle/crypto/signers/DSAKCalculator;
    //   42: invokeinterface nextK : ()Ljava/math/BigInteger;
    //   47: astore #8
    //   49: aload #7
    //   51: aload_0
    //   52: getfield ecParams : Lorg/bouncycastle/crypto/params/ECDomainParameters;
    //   55: invokevirtual getG : ()Lorg/bouncycastle/math/ec/ECPoint;
    //   58: aload #8
    //   60: invokeinterface multiply : (Lorg/bouncycastle/math/ec/ECPoint;Ljava/math/BigInteger;)Lorg/bouncycastle/math/ec/ECPoint;
    //   65: invokevirtual normalize : ()Lorg/bouncycastle/math/ec/ECPoint;
    //   68: astore #9
    //   70: aload_3
    //   71: aload #9
    //   73: invokevirtual getAffineXCoord : ()Lorg/bouncycastle/math/ec/ECFieldElement;
    //   76: invokevirtual toBigInteger : ()Ljava/math/BigInteger;
    //   79: invokevirtual add : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   82: aload_2
    //   83: invokevirtual mod : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   86: astore #5
    //   88: aload #5
    //   90: getstatic org/bouncycastle/crypto/signers/SM2Signer.ZERO : Ljava/math/BigInteger;
    //   93: invokevirtual equals : (Ljava/lang/Object;)Z
    //   96: ifne -> 38
    //   99: aload #5
    //   101: aload #8
    //   103: invokevirtual add : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   106: aload_2
    //   107: invokevirtual equals : (Ljava/lang/Object;)Z
    //   110: ifne -> 38
    //   113: aload_2
    //   114: aload #4
    //   116: getstatic org/bouncycastle/crypto/signers/SM2Signer.ONE : Ljava/math/BigInteger;
    //   119: invokevirtual add : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   122: invokestatic modOddInverse : (Ljava/math/BigInteger;Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   125: astore #9
    //   127: aload #8
    //   129: aload #5
    //   131: aload #4
    //   133: invokevirtual multiply : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   136: invokevirtual subtract : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   139: aload_2
    //   140: invokevirtual mod : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   143: astore #6
    //   145: aload #9
    //   147: aload #6
    //   149: invokevirtual multiply : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   152: aload_2
    //   153: invokevirtual mod : (Ljava/math/BigInteger;)Ljava/math/BigInteger;
    //   156: astore #6
    //   158: aload #6
    //   160: getstatic org/bouncycastle/crypto/signers/SM2Signer.ZERO : Ljava/math/BigInteger;
    //   163: invokevirtual equals : (Ljava/lang/Object;)Z
    //   166: ifne -> 38
    //   169: aload_0
    //   170: getfield encoding : Lorg/bouncycastle/crypto/signers/DSAEncoding;
    //   173: aload_0
    //   174: getfield ecParams : Lorg/bouncycastle/crypto/params/ECDomainParameters;
    //   177: invokevirtual getN : ()Ljava/math/BigInteger;
    //   180: aload #5
    //   182: aload #6
    //   184: invokeinterface encode : (Ljava/math/BigInteger;Ljava/math/BigInteger;Ljava/math/BigInteger;)[B
    //   189: areturn
    //   190: astore #8
    //   192: new org/bouncycastle/crypto/CryptoException
    //   195: dup
    //   196: new java/lang/StringBuilder
    //   199: dup
    //   200: invokespecial <init> : ()V
    //   203: ldc 'unable to encode signature: '
    //   205: invokevirtual append : (Ljava/lang/String;)Ljava/lang/StringBuilder;
    //   208: aload #8
    //   210: invokevirtual getMessage : ()Ljava/lang/String;
    //   213: invokevirtual append : (Ljava/lang/String;)Ljava/lang/StringBuilder;
    //   216: invokevirtual toString : ()Ljava/lang/String;
    //   219: aload #8
    //   221: invokespecial <init> : (Ljava/lang/String;Ljava/lang/Throwable;)V
    //   224: athrow
    // Exception table:
    //   from	to	target	type
    //   169	189	190	java/lang/Exception
  }
  
  private boolean verifySignature(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    BigInteger bigInteger1 = this.ecParams.getN();
    if (paramBigInteger1.compareTo(ONE) < 0 || paramBigInteger1.compareTo(bigInteger1) >= 0)
      return false; 
    if (paramBigInteger2.compareTo(ONE) < 0 || paramBigInteger2.compareTo(bigInteger1) >= 0)
      return false; 
    byte[] arrayOfByte = digestDoFinal();
    BigInteger bigInteger2 = calculateE(bigInteger1, arrayOfByte);
    BigInteger bigInteger3 = paramBigInteger1.add(paramBigInteger2).mod(bigInteger1);
    if (bigInteger3.equals(ZERO))
      return false; 
    ECPoint eCPoint1 = ((ECPublicKeyParameters)this.ecKey).getQ();
    ECPoint eCPoint2 = ECAlgorithms.sumOfTwoMultiplies(this.ecParams.getG(), paramBigInteger2, eCPoint1, bigInteger3).normalize();
    if (eCPoint2.isInfinity())
      return false; 
    BigInteger bigInteger4 = bigInteger2.add(eCPoint2.getAffineXCoord().toBigInteger()).mod(bigInteger1);
    return bigInteger4.equals(paramBigInteger1);
  }
  
  private byte[] digestDoFinal() {
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
    reset();
    return arrayOfByte;
  }
  
  private byte[] getZ(byte[] paramArrayOfbyte) {
    this.digest.reset();
    addUserID(this.digest, paramArrayOfbyte);
    addFieldElement(this.digest, this.ecParams.getCurve().getA());
    addFieldElement(this.digest, this.ecParams.getCurve().getB());
    addFieldElement(this.digest, this.ecParams.getG().getAffineXCoord());
    addFieldElement(this.digest, this.ecParams.getG().getAffineYCoord());
    addFieldElement(this.digest, this.pubPoint.getAffineXCoord());
    addFieldElement(this.digest, this.pubPoint.getAffineYCoord());
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
    return arrayOfByte;
  }
  
  private void addUserID(Digest paramDigest, byte[] paramArrayOfbyte) {
    int i = paramArrayOfbyte.length * 8;
    paramDigest.update((byte)(i >> 8 & 0xFF));
    paramDigest.update((byte)(i & 0xFF));
    paramDigest.update(paramArrayOfbyte, 0, paramArrayOfbyte.length);
  }
  
  private void addFieldElement(Digest paramDigest, ECFieldElement paramECFieldElement) {
    byte[] arrayOfByte = paramECFieldElement.getEncoded();
    paramDigest.update(arrayOfByte, 0, arrayOfByte.length);
  }
  
  protected ECMultiplier createBasePointMultiplier() {
    return new FixedPointCombMultiplier();
  }
  
  protected BigInteger calculateE(BigInteger paramBigInteger, byte[] paramArrayOfbyte) {
    return new BigInteger(1, paramArrayOfbyte);
  }
}
