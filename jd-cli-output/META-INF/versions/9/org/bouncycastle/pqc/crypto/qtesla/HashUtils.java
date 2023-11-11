package META-INF.versions.9.org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.digests.CSHAKEDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

class HashUtils {
  static final int SECURE_HASH_ALGORITHM_KECCAK_128_RATE = 168;
  
  static final int SECURE_HASH_ALGORITHM_KECCAK_256_RATE = 136;
  
  static void secureHashAlgorithmKECCAK128(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3, int paramInt4) {
    SHAKEDigest sHAKEDigest = new SHAKEDigest(128);
    sHAKEDigest.update(paramArrayOfbyte2, paramInt3, paramInt4);
    sHAKEDigest.doFinal(paramArrayOfbyte1, paramInt1, paramInt2);
  }
  
  static void secureHashAlgorithmKECCAK256(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3, int paramInt4) {
    SHAKEDigest sHAKEDigest = new SHAKEDigest(256);
    sHAKEDigest.update(paramArrayOfbyte2, paramInt3, paramInt4);
    sHAKEDigest.doFinal(paramArrayOfbyte1, paramInt1, paramInt2);
  }
  
  static void customizableSecureHashAlgorithmKECCAK128Simple(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, short paramShort, byte[] paramArrayOfbyte2, int paramInt3, int paramInt4) {
    CSHAKEDigest cSHAKEDigest = new CSHAKEDigest(128, null, new byte[] { (byte)paramShort, (byte)(paramShort >> 8) });
    cSHAKEDigest.update(paramArrayOfbyte2, paramInt3, paramInt4);
    cSHAKEDigest.doFinal(paramArrayOfbyte1, paramInt1, paramInt2);
  }
  
  static void customizableSecureHashAlgorithmKECCAK256Simple(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, short paramShort, byte[] paramArrayOfbyte2, int paramInt3, int paramInt4) {
    CSHAKEDigest cSHAKEDigest = new CSHAKEDigest(256, null, new byte[] { (byte)paramShort, (byte)(paramShort >> 8) });
    cSHAKEDigest.update(paramArrayOfbyte2, paramInt3, paramInt4);
    cSHAKEDigest.doFinal(paramArrayOfbyte1, paramInt1, paramInt2);
  }
}
