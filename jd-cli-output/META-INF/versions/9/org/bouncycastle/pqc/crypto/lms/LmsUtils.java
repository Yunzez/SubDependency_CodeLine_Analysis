package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

class LmsUtils {
  static void u32str(int paramInt, Digest paramDigest) {
    paramDigest.update((byte)(paramInt >>> 24));
    paramDigest.update((byte)(paramInt >>> 16));
    paramDigest.update((byte)(paramInt >>> 8));
    paramDigest.update((byte)paramInt);
  }
  
  static void u16str(short paramShort, Digest paramDigest) {
    paramDigest.update((byte)(paramShort >>> 8));
    paramDigest.update((byte)paramShort);
  }
  
  static void byteArray(byte[] paramArrayOfbyte, Digest paramDigest) {
    paramDigest.update(paramArrayOfbyte, 0, paramArrayOfbyte.length);
  }
  
  static void byteArray(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, Digest paramDigest) {
    paramDigest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  static int calculateStrength(LMSParameters paramLMSParameters) {
    if (paramLMSParameters == null)
      throw new NullPointerException("lmsParameters cannot be null"); 
    LMSigParameters lMSigParameters = paramLMSParameters.getLMSigParam();
    return (1 << lMSigParameters.getH()) * lMSigParameters.getM();
  }
}
