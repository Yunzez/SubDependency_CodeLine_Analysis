package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.lms.DigestUtil;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMOtsSignature;
import org.bouncycastle.pqc.crypto.lms.LMSContext;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSignature;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.crypto.lms.LM_OTS;
import org.bouncycastle.pqc.crypto.lms.LmsUtils;

class LMS {
  static final short D_LEAF = -32126;
  
  static final short D_INTR = -31869;
  
  public static LMSPrivateKeyParameters generateKeys(LMSigParameters paramLMSigParameters, LMOtsParameters paramLMOtsParameters, int paramInt, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws IllegalArgumentException {
    if (paramArrayOfbyte2 == null || paramArrayOfbyte2.length < paramLMSigParameters.getM())
      throw new IllegalArgumentException("root seed is less than " + paramLMSigParameters.getM()); 
    int i = 1 << paramLMSigParameters.getH();
    return new LMSPrivateKeyParameters(paramLMSigParameters, paramLMOtsParameters, paramInt, paramArrayOfbyte1, i, paramArrayOfbyte2);
  }
  
  public static LMSSignature generateSign(LMSPrivateKeyParameters paramLMSPrivateKeyParameters, byte[] paramArrayOfbyte) {
    LMSContext lMSContext = paramLMSPrivateKeyParameters.generateLMSContext();
    lMSContext.update(paramArrayOfbyte, 0, paramArrayOfbyte.length);
    return generateSign(lMSContext);
  }
  
  public static LMSSignature generateSign(LMSContext paramLMSContext) {
    LMOtsSignature lMOtsSignature = LM_OTS.lm_ots_generate_signature(paramLMSContext.getPrivateKey(), paramLMSContext.getQ(), paramLMSContext.getC());
    return new LMSSignature(paramLMSContext.getPrivateKey().getQ(), lMOtsSignature, paramLMSContext.getSigParams(), paramLMSContext.getPath());
  }
  
  public static boolean verifySignature(LMSPublicKeyParameters paramLMSPublicKeyParameters, LMSSignature paramLMSSignature, byte[] paramArrayOfbyte) {
    LMSContext lMSContext = paramLMSPublicKeyParameters.generateOtsContext(paramLMSSignature);
    LmsUtils.byteArray(paramArrayOfbyte, lMSContext);
    return verifySignature(paramLMSPublicKeyParameters, lMSContext);
  }
  
  public static boolean verifySignature(LMSPublicKeyParameters paramLMSPublicKeyParameters, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    LMSContext lMSContext = paramLMSPublicKeyParameters.generateLMSContext(paramArrayOfbyte1);
    LmsUtils.byteArray(paramArrayOfbyte2, lMSContext);
    return verifySignature(paramLMSPublicKeyParameters, lMSContext);
  }
  
  public static boolean verifySignature(LMSPublicKeyParameters paramLMSPublicKeyParameters, LMSContext paramLMSContext) {
    LMSSignature lMSSignature = (LMSSignature)paramLMSContext.getSignature();
    LMSigParameters lMSigParameters = lMSSignature.getParameter();
    int i = lMSigParameters.getH();
    byte[][] arrayOfByte = lMSSignature.getY();
    byte[] arrayOfByte1 = LM_OTS.lm_ots_validate_signature_calculate(paramLMSContext);
    int j = (1 << i) + lMSSignature.getQ();
    byte[] arrayOfByte2 = paramLMSPublicKeyParameters.getI();
    Digest digest = DigestUtil.getDigest(lMSigParameters.getDigestOID());
    byte[] arrayOfByte3 = new byte[digest.getDigestSize()];
    digest.update(arrayOfByte2, 0, arrayOfByte2.length);
    LmsUtils.u32str(j, digest);
    LmsUtils.u16str((short)-32126, digest);
    digest.update(arrayOfByte1, 0, arrayOfByte1.length);
    digest.doFinal(arrayOfByte3, 0);
    byte b = 0;
    while (j > 1) {
      if ((j & 0x1) == 1) {
        digest.update(arrayOfByte2, 0, arrayOfByte2.length);
        LmsUtils.u32str(j / 2, digest);
        LmsUtils.u16str((short)-31869, digest);
        digest.update(arrayOfByte[b], 0, (arrayOfByte[b]).length);
        digest.update(arrayOfByte3, 0, arrayOfByte3.length);
        digest.doFinal(arrayOfByte3, 0);
      } else {
        digest.update(arrayOfByte2, 0, arrayOfByte2.length);
        LmsUtils.u32str(j / 2, digest);
        LmsUtils.u16str((short)-31869, digest);
        digest.update(arrayOfByte3, 0, arrayOfByte3.length);
        digest.update(arrayOfByte[b], 0, (arrayOfByte[b]).length);
        digest.doFinal(arrayOfByte3, 0);
      } 
      j /= 2;
      b++;
    } 
    byte[] arrayOfByte4 = arrayOfByte3;
    return paramLMSPublicKeyParameters.matchesT1(arrayOfByte4);
  }
}
