package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class LM_OTS {
  private static final short D_PBLC = -32640;
  
  private static final int ITER_K = 20;
  
  private static final int ITER_PREV = 23;
  
  private static final int ITER_J = 22;
  
  static final int SEED_RANDOMISER_INDEX = -3;
  
  static final int SEED_LEN = 32;
  
  static final int MAX_HASH = 32;
  
  static final short D_MESG = -32383;
  
  public static int coef(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    int i = paramInt1 * paramInt2 / 8;
    int j = 8 / paramInt2;
    int k = paramInt2 * ((paramInt1 ^ 0xFFFFFFFF) & j - 1);
    int m = (1 << paramInt2) - 1;
    return paramArrayOfbyte[i] >>> k & m;
  }
  
  public static int cksm(byte[] paramArrayOfbyte, int paramInt, LMOtsParameters paramLMOtsParameters) {
    int i = 0;
    int j = paramLMOtsParameters.getW();
    int k = (1 << j) - 1;
    for (byte b = 0; b < paramInt * 8 / paramLMOtsParameters.getW(); b++)
      i = i + k - coef(paramArrayOfbyte, b, paramLMOtsParameters.getW()); 
    return i << paramLMOtsParameters.getLs();
  }
  
  public static LMOtsPublicKey lms_ots_generatePublicKey(LMOtsPrivateKey paramLMOtsPrivateKey) {
    byte[] arrayOfByte = lms_ots_generatePublicKey(paramLMOtsPrivateKey.getParameter(), paramLMOtsPrivateKey.getI(), paramLMOtsPrivateKey.getQ(), paramLMOtsPrivateKey.getMasterSecret());
    return new LMOtsPublicKey(paramLMOtsPrivateKey.getParameter(), paramLMOtsPrivateKey.getI(), paramLMOtsPrivateKey.getQ(), arrayOfByte);
  }
  
  static byte[] lms_ots_generatePublicKey(LMOtsParameters paramLMOtsParameters, byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2) {
    Digest digest1 = DigestUtil.getDigest(paramLMOtsParameters.getDigestOID());
    byte[] arrayOfByte1 = Composer.compose().bytes(paramArrayOfbyte1).u32str(paramInt).u16str(-32640).padUntil(0, 22).build();
    digest1.update(arrayOfByte1, 0, arrayOfByte1.length);
    Digest digest2 = DigestUtil.getDigest(paramLMOtsParameters.getDigestOID());
    byte[] arrayOfByte2 = Composer.compose().bytes(paramArrayOfbyte1).u32str(paramInt).padUntil(0, 23 + digest2.getDigestSize()).build();
    SeedDerive seedDerive = new SeedDerive(paramArrayOfbyte1, paramArrayOfbyte2, DigestUtil.getDigest(paramLMOtsParameters.getDigestOID()));
    seedDerive.setQ(paramInt);
    seedDerive.setJ(0);
    int i = paramLMOtsParameters.getP();
    int j = paramLMOtsParameters.getN();
    int k = (1 << paramLMOtsParameters.getW()) - 1;
    for (byte b = 0; b < i; b++) {
      seedDerive.deriveSeed(arrayOfByte2, (b < i - 1), 23);
      Pack.shortToBigEndian((short)b, arrayOfByte2, 20);
      for (byte b1 = 0; b1 < k; b1++) {
        arrayOfByte2[22] = (byte)b1;
        digest2.update(arrayOfByte2, 0, arrayOfByte2.length);
        digest2.doFinal(arrayOfByte2, 23);
      } 
      digest1.update(arrayOfByte2, 23, j);
    } 
    byte[] arrayOfByte3 = new byte[digest1.getDigestSize()];
    digest1.doFinal(arrayOfByte3, 0);
    return arrayOfByte3;
  }
  
  public static LMOtsSignature lm_ots_generate_signature(LMSigParameters paramLMSigParameters, LMOtsPrivateKey paramLMOtsPrivateKey, byte[][] paramArrayOfbyte, byte[] paramArrayOfbyte1, boolean paramBoolean) {
    byte[] arrayOfByte1;
    byte[] arrayOfByte2 = new byte[34];
    if (!paramBoolean) {
      LMSContext lMSContext = paramLMOtsPrivateKey.getSignatureContext(paramLMSigParameters, paramArrayOfbyte);
      LmsUtils.byteArray(paramArrayOfbyte1, 0, paramArrayOfbyte1.length, lMSContext);
      arrayOfByte1 = lMSContext.getC();
      arrayOfByte2 = lMSContext.getQ();
    } else {
      arrayOfByte1 = new byte[32];
      System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte2, 0, paramLMOtsPrivateKey.getParameter().getN());
    } 
    return lm_ots_generate_signature(paramLMOtsPrivateKey, arrayOfByte2, arrayOfByte1);
  }
  
  public static LMOtsSignature lm_ots_generate_signature(LMOtsPrivateKey paramLMOtsPrivateKey, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    LMOtsParameters lMOtsParameters = paramLMOtsPrivateKey.getParameter();
    int i = lMOtsParameters.getN();
    int j = lMOtsParameters.getP();
    int k = lMOtsParameters.getW();
    byte[] arrayOfByte1 = new byte[j * i];
    Digest digest = DigestUtil.getDigest(lMOtsParameters.getDigestOID());
    SeedDerive seedDerive = paramLMOtsPrivateKey.getDerivationFunction();
    int m = cksm(paramArrayOfbyte1, i, lMOtsParameters);
    paramArrayOfbyte1[i] = (byte)(m >>> 8 & 0xFF);
    paramArrayOfbyte1[i + 1] = (byte)m;
    byte[] arrayOfByte2 = Composer.compose().bytes(paramLMOtsPrivateKey.getI()).u32str(paramLMOtsPrivateKey.getQ()).padUntil(0, 23 + i).build();
    seedDerive.setJ(0);
    for (byte b = 0; b < j; b++) {
      Pack.shortToBigEndian((short)b, arrayOfByte2, 20);
      seedDerive.deriveSeed(arrayOfByte2, (b < j - 1), 23);
      int n = coef(paramArrayOfbyte1, b, k);
      for (byte b1 = 0; b1 < n; b1++) {
        arrayOfByte2[22] = (byte)b1;
        digest.update(arrayOfByte2, 0, 23 + i);
        digest.doFinal(arrayOfByte2, 23);
      } 
      System.arraycopy(arrayOfByte2, 23, arrayOfByte1, i * b, i);
    } 
    return new LMOtsSignature(lMOtsParameters, paramArrayOfbyte2, arrayOfByte1);
  }
  
  public static boolean lm_ots_validate_signature(LMOtsPublicKey paramLMOtsPublicKey, LMOtsSignature paramLMOtsSignature, byte[] paramArrayOfbyte, boolean paramBoolean) throws LMSException {
    if (!paramLMOtsSignature.getType().equals(paramLMOtsPublicKey.getParameter()))
      throw new LMSException("public key and signature ots types do not match"); 
    return Arrays.areEqual(lm_ots_validate_signature_calculate(paramLMOtsPublicKey, paramLMOtsSignature, paramArrayOfbyte), paramLMOtsPublicKey.getK());
  }
  
  public static byte[] lm_ots_validate_signature_calculate(LMOtsPublicKey paramLMOtsPublicKey, LMOtsSignature paramLMOtsSignature, byte[] paramArrayOfbyte) {
    LMSContext lMSContext = paramLMOtsPublicKey.createOtsContext(paramLMOtsSignature);
    LmsUtils.byteArray(paramArrayOfbyte, lMSContext);
    return lm_ots_validate_signature_calculate(lMSContext);
  }
  
  public static byte[] lm_ots_validate_signature_calculate(LMSContext paramLMSContext) {
    LMOtsSignature lMOtsSignature;
    LMOtsPublicKey lMOtsPublicKey = paramLMSContext.getPublicKey();
    LMOtsParameters lMOtsParameters = lMOtsPublicKey.getParameter();
    Object object = paramLMSContext.getSignature();
    if (object instanceof LMSSignature) {
      lMOtsSignature = ((LMSSignature)object).getOtsSignature();
    } else {
      lMOtsSignature = (LMOtsSignature)object;
    } 
    int i = lMOtsParameters.getN();
    int j = lMOtsParameters.getW();
    int k = lMOtsParameters.getP();
    byte[] arrayOfByte1 = paramLMSContext.getQ();
    int m = cksm(arrayOfByte1, i, lMOtsParameters);
    arrayOfByte1[i] = (byte)(m >>> 8 & 0xFF);
    arrayOfByte1[i + 1] = (byte)m;
    byte[] arrayOfByte2 = lMOtsPublicKey.getI();
    int n = lMOtsPublicKey.getQ();
    Digest digest1 = DigestUtil.getDigest(lMOtsParameters.getDigestOID());
    LmsUtils.byteArray(arrayOfByte2, digest1);
    LmsUtils.u32str(n, digest1);
    LmsUtils.u16str((short)-32640, digest1);
    byte[] arrayOfByte3 = Composer.compose().bytes(arrayOfByte2).u32str(n).padUntil(0, 23 + i).build();
    int i1 = (1 << j) - 1;
    byte[] arrayOfByte4 = lMOtsSignature.getY();
    Digest digest2 = DigestUtil.getDigest(lMOtsParameters.getDigestOID());
    for (byte b = 0; b < k; b++) {
      Pack.shortToBigEndian((short)b, arrayOfByte3, 20);
      System.arraycopy(arrayOfByte4, b * i, arrayOfByte3, 23, i);
      int i2 = coef(arrayOfByte1, b, j);
      for (int i3 = i2; i3 < i1; i3++) {
        arrayOfByte3[22] = (byte)i3;
        digest2.update(arrayOfByte3, 0, 23 + i);
        digest2.doFinal(arrayOfByte3, 23);
      } 
      digest1.update(arrayOfByte3, 23, i);
    } 
    byte[] arrayOfByte5 = new byte[i];
    digest1.doFinal(arrayOfByte5, 0);
    return arrayOfByte5;
  }
}
