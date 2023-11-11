package META-INF.versions.9.org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.qtesla.HashUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class QTesla3p {
  private static final int PARAM_N = 2048;
  
  private static final int PARAM_Q = 856145921;
  
  private static final int PARAM_Q_LOG = 30;
  
  private static final long PARAM_QINV = 587710463L;
  
  private static final long PARAM_BARR_MULT = 5L;
  
  private static final int PARAM_BARR_DIV = 32;
  
  private static final int PARAM_B = 2097151;
  
  private static final int PARAM_B_BITS = 21;
  
  private static final int PARAM_K = 5;
  
  private static final int PARAM_H = 40;
  
  private static final int PARAM_D = 24;
  
  private static final int PARAM_GEN_A = 180;
  
  private static final int PARAM_KEYGEN_BOUND_E = 901;
  
  private static final int PARAM_E = 901;
  
  private static final int PARAM_KEYGEN_BOUND_S = 901;
  
  private static final int PARAM_S = 901;
  
  private static final int PARAM_R2_INVN = 513161157;
  
  private static final int CRYPTO_RANDOMBYTES = 32;
  
  private static final int CRYPTO_SEEDBYTES = 32;
  
  private static final int CRYPTO_C_BYTES = 32;
  
  private static final int HM_BYTES = 40;
  
  private static final int RADIX32 = 32;
  
  static final int CRYPTO_BYTES = 5664;
  
  static final int CRYPTO_SECRETKEYBYTES = 12392;
  
  static final int CRYPTO_PUBLICKEYBYTES = 38432;
  
  private static final int maskb1 = 4194303;
  
  static int generateKeyPair(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, SecureRandom paramSecureRandom) {
    byte b1 = 0;
    byte[] arrayOfByte1 = new byte[32];
    byte[] arrayOfByte2 = new byte[256];
    long[] arrayOfLong1 = new long[2048];
    long[] arrayOfLong2 = new long[10240];
    long[] arrayOfLong3 = new long[10240];
    long[] arrayOfLong4 = new long[10240];
    long[] arrayOfLong5 = new long[2048];
    paramSecureRandom.nextBytes(arrayOfByte1);
    HashUtils.secureHashAlgorithmKECCAK256(arrayOfByte2, 0, 256, arrayOfByte1, 0, 32);
    byte b2;
    for (b2 = 0; b2 < 5;) {
      while (true) {
        Gaussian.sample_gauss_poly(++b1, arrayOfByte2, b2 * 32, arrayOfLong2, b2 * 2048);
        if (!checkPolynomial(arrayOfLong2, b2 * 2048, 901))
          b2++; 
      } 
    } 
    do {
      Gaussian.sample_gauss_poly(++b1, arrayOfByte2, 160, arrayOfLong1, 0);
    } while (checkPolynomial(arrayOfLong1, 0, 901));
    QTesla3PPolynomial.poly_uniform(arrayOfLong3, arrayOfByte2, 192);
    QTesla3PPolynomial.poly_ntt(arrayOfLong5, arrayOfLong1);
    for (b2 = 0; b2 < 5; b2++) {
      QTesla3PPolynomial.poly_mul(arrayOfLong4, b2 * 2048, arrayOfLong3, b2 * 2048, arrayOfLong5);
      QTesla3PPolynomial.poly_add_correct(arrayOfLong4, b2 * 2048, arrayOfLong4, b2 * 2048, arrayOfLong2, b2 * 2048);
    } 
    encodePublicKey(paramArrayOfbyte1, arrayOfLong4, arrayOfByte2, 192);
    encodePrivateKey(paramArrayOfbyte2, arrayOfLong1, arrayOfLong2, arrayOfByte2, 192, paramArrayOfbyte1);
    return 0;
  }
  
  static int generateSignature(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2, byte[] paramArrayOfbyte3, SecureRandom paramSecureRandom) {
    byte[] arrayOfByte1 = new byte[32];
    byte[] arrayOfByte2 = new byte[32];
    byte[] arrayOfByte3 = new byte[144];
    int[] arrayOfInt = new int[40];
    short[] arrayOfShort = new short[40];
    long[] arrayOfLong1 = new long[2048];
    long[] arrayOfLong2 = new long[2048];
    long[] arrayOfLong3 = new long[2048];
    long[] arrayOfLong4 = new long[2048];
    long[] arrayOfLong5 = new long[10240];
    long[] arrayOfLong6 = new long[10240];
    long[] arrayOfLong7 = new long[10240];
    byte b = 0;
    boolean bool = false;
    System.arraycopy(paramArrayOfbyte3, 12320, arrayOfByte3, 0, 32);
    byte[] arrayOfByte4 = new byte[32];
    paramSecureRandom.nextBytes(arrayOfByte4);
    System.arraycopy(arrayOfByte4, 0, arrayOfByte3, 32, 32);
    HashUtils.secureHashAlgorithmKECCAK256(arrayOfByte3, 64, 40, paramArrayOfbyte2, 0, paramInt2);
    HashUtils.secureHashAlgorithmKECCAK256(arrayOfByte2, 0, 32, arrayOfByte3, 0, arrayOfByte3.length - 40);
    System.arraycopy(paramArrayOfbyte3, 12352, arrayOfByte3, arrayOfByte3.length - 40, 40);
    QTesla3PPolynomial.poly_uniform(arrayOfLong7, paramArrayOfbyte3, 12288);
    while (true) {
      sample_y(arrayOfLong1, arrayOfByte2, 0, ++b);
      QTesla3PPolynomial.poly_ntt(arrayOfLong2, arrayOfLong1);
      byte b1;
      for (b1 = 0; b1 < 5; b1++)
        QTesla3PPolynomial.poly_mul(arrayOfLong5, b1 * 2048, arrayOfLong7, b1 * 2048, arrayOfLong2); 
      hashFunction(arrayOfByte1, 0, arrayOfLong5, arrayOfByte3, 64);
      encodeC(arrayOfInt, arrayOfShort, arrayOfByte1, 0);
      QTesla3PPolynomial.sparse_mul8(arrayOfLong3, paramArrayOfbyte3, arrayOfInt, arrayOfShort);
      QTesla3PPolynomial.poly_add(arrayOfLong4, arrayOfLong1, arrayOfLong3);
      if (testRejection(arrayOfLong4))
        continue; 
      for (b1 = 0; b1 < 5; b1++) {
        QTesla3PPolynomial.sparse_mul8(arrayOfLong6, b1 * 2048, paramArrayOfbyte3, 2048 * (b1 + 1), arrayOfInt, arrayOfShort);
        QTesla3PPolynomial.poly_sub(arrayOfLong5, b1 * 2048, arrayOfLong5, b1 * 2048, arrayOfLong6, b1 * 2048);
        bool = test_correctness(arrayOfLong5, b1 * 2048);
        if (bool)
          break; 
      } 
      if (bool)
        continue; 
      break;
    } 
    encodeSignature(paramArrayOfbyte1, 0, arrayOfByte1, 0, arrayOfLong4);
    return 0;
  }
  
  static int verifying(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2, byte[] paramArrayOfbyte3) {
    byte[] arrayOfByte1 = new byte[32];
    byte[] arrayOfByte2 = new byte[32];
    byte[] arrayOfByte3 = new byte[32];
    byte[] arrayOfByte4 = new byte[80];
    int[] arrayOfInt1 = new int[40];
    short[] arrayOfShort = new short[40];
    int[] arrayOfInt2 = new int[10240];
    long[] arrayOfLong1 = new long[10240];
    long[] arrayOfLong2 = new long[10240];
    long[] arrayOfLong3 = new long[10240];
    long[] arrayOfLong4 = new long[2048];
    long[] arrayOfLong5 = new long[2048];
    byte b = 0;
    if (paramInt2 != 5664)
      return -1; 
    decodeSignature(arrayOfByte1, arrayOfLong4, paramArrayOfbyte2, paramInt1);
    if (testZ(arrayOfLong4))
      return -2; 
    decodePublicKey(arrayOfInt2, arrayOfByte3, 0, paramArrayOfbyte3);
    HashUtils.secureHashAlgorithmKECCAK256(arrayOfByte4, 0, 40, paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
    HashUtils.secureHashAlgorithmKECCAK256(arrayOfByte4, 40, 40, paramArrayOfbyte3, 0, 38400);
    QTesla3PPolynomial.poly_uniform(arrayOfLong2, arrayOfByte3, 0);
    encodeC(arrayOfInt1, arrayOfShort, arrayOfByte1, 0);
    QTesla3PPolynomial.poly_ntt(arrayOfLong5, arrayOfLong4);
    for (b = 0; b < 5; b++) {
      QTesla3PPolynomial.sparse_mul32(arrayOfLong3, b * 2048, arrayOfInt2, b * 2048, arrayOfInt1, arrayOfShort);
      QTesla3PPolynomial.poly_mul(arrayOfLong1, b * 2048, arrayOfLong2, b * 2048, arrayOfLong5);
      QTesla3PPolynomial.poly_sub(arrayOfLong1, b * 2048, arrayOfLong1, b * 2048, arrayOfLong3, b * 2048);
    } 
    hashFunction(arrayOfByte2, 0, arrayOfLong1, arrayOfByte4, 0);
    if (!memoryEqual(arrayOfByte1, 0, arrayOfByte2, 0, 32))
      return -3; 
    return 0;
  }
  
  static void encodePrivateKey(byte[] paramArrayOfbyte1, long[] paramArrayOflong1, long[] paramArrayOflong2, byte[] paramArrayOfbyte2, int paramInt, byte[] paramArrayOfbyte3) {
    byte b2 = 0;
    byte b3 = 0;
    byte b1;
    for (b1 = 0; b1 < 'ࠀ'; b1++)
      paramArrayOfbyte1[b3 + b1] = (byte)(int)paramArrayOflong1[b1]; 
    b3 += 2048;
    for (b2 = 0; b2 < 5; b2++) {
      for (b1 = 0; b1 < 'ࠀ'; b1++)
        paramArrayOfbyte1[b3 + b2 * 2048 + b1] = (byte)(int)paramArrayOflong2[b2 * 2048 + b1]; 
    } 
    b3 += 10240;
    System.arraycopy(paramArrayOfbyte2, paramInt, paramArrayOfbyte1, b3, 64);
    b3 += 64;
    HashUtils.secureHashAlgorithmKECCAK256(paramArrayOfbyte1, b3, 40, paramArrayOfbyte3, 0, 38400);
    b3 += 40;
  }
  
  static void encodePublicKey(byte[] paramArrayOfbyte1, long[] paramArrayOflong, byte[] paramArrayOfbyte2, int paramInt) {
    byte b1 = 0;
    for (byte b2 = 0; b2 < '▀'; b2 += 15) {
      at(paramArrayOfbyte1, b2, 0, (int)(paramArrayOflong[b1] | paramArrayOflong[b1 + 1] << 30L));
      at(paramArrayOfbyte1, b2, 1, (int)(paramArrayOflong[b1 + 1] >> 2L | paramArrayOflong[b1 + 2] << 28L));
      at(paramArrayOfbyte1, b2, 2, (int)(paramArrayOflong[b1 + 2] >> 4L | paramArrayOflong[b1 + 3] << 26L));
      at(paramArrayOfbyte1, b2, 3, (int)(paramArrayOflong[b1 + 3] >> 6L | paramArrayOflong[b1 + 4] << 24L));
      at(paramArrayOfbyte1, b2, 4, (int)(paramArrayOflong[b1 + 4] >> 8L | paramArrayOflong[b1 + 5] << 22L));
      at(paramArrayOfbyte1, b2, 5, (int)(paramArrayOflong[b1 + 5] >> 10L | paramArrayOflong[b1 + 6] << 20L));
      at(paramArrayOfbyte1, b2, 6, (int)(paramArrayOflong[b1 + 6] >> 12L | paramArrayOflong[b1 + 7] << 18L));
      at(paramArrayOfbyte1, b2, 7, (int)(paramArrayOflong[b1 + 7] >> 14L | paramArrayOflong[b1 + 8] << 16L));
      at(paramArrayOfbyte1, b2, 8, (int)(paramArrayOflong[b1 + 8] >> 16L | paramArrayOflong[b1 + 9] << 14L));
      at(paramArrayOfbyte1, b2, 9, (int)(paramArrayOflong[b1 + 9] >> 18L | paramArrayOflong[b1 + 10] << 12L));
      at(paramArrayOfbyte1, b2, 10, (int)(paramArrayOflong[b1 + 10] >> 20L | paramArrayOflong[b1 + 11] << 10L));
      at(paramArrayOfbyte1, b2, 11, (int)(paramArrayOflong[b1 + 11] >> 22L | paramArrayOflong[b1 + 12] << 8L));
      at(paramArrayOfbyte1, b2, 12, (int)(paramArrayOflong[b1 + 12] >> 24L | paramArrayOflong[b1 + 13] << 6L));
      at(paramArrayOfbyte1, b2, 13, (int)(paramArrayOflong[b1 + 13] >> 26L | paramArrayOflong[b1 + 14] << 4L));
      at(paramArrayOfbyte1, b2, 14, (int)(paramArrayOflong[b1 + 14] >> 28L | paramArrayOflong[b1 + 15] << 2L));
      b1 += 16;
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt, paramArrayOfbyte1, 38400, 32);
  }
  
  static void decodePublicKey(int[] paramArrayOfint, byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2) {
    boolean bool = false;
    byte[] arrayOfByte = paramArrayOfbyte2;
    int i = 1073741823;
    for (byte b = 0; b < '⠀'; b += 16) {
      paramArrayOfint[b] = at(arrayOfByte, bool, 0) & i;
      paramArrayOfint[b + 1] = (at(arrayOfByte, bool, 0) >>> 30 | at(arrayOfByte, bool, 1) << 2) & i;
      paramArrayOfint[b + 2] = (at(arrayOfByte, bool, 1) >>> 28 | at(arrayOfByte, bool, 2) << 4) & i;
      paramArrayOfint[b + 3] = (at(arrayOfByte, bool, 2) >>> 26 | at(arrayOfByte, bool, 3) << 6) & i;
      paramArrayOfint[b + 4] = (at(arrayOfByte, bool, 3) >>> 24 | at(arrayOfByte, bool, 4) << 8) & i;
      paramArrayOfint[b + 5] = (at(arrayOfByte, bool, 4) >>> 22 | at(arrayOfByte, bool, 5) << 10) & i;
      paramArrayOfint[b + 6] = (at(arrayOfByte, bool, 5) >>> 20 | at(arrayOfByte, bool, 6) << 12) & i;
      paramArrayOfint[b + 7] = (at(arrayOfByte, bool, 6) >>> 18 | at(arrayOfByte, bool, 7) << 14) & i;
      paramArrayOfint[b + 8] = (at(arrayOfByte, bool, 7) >>> 16 | at(arrayOfByte, bool, 8) << 16) & i;
      paramArrayOfint[b + 9] = (at(arrayOfByte, bool, 8) >>> 14 | at(arrayOfByte, bool, 9) << 18) & i;
      paramArrayOfint[b + 10] = (at(arrayOfByte, bool, 9) >>> 12 | at(arrayOfByte, bool, 10) << 20) & i;
      paramArrayOfint[b + 11] = (at(arrayOfByte, bool, 10) >>> 10 | at(arrayOfByte, bool, 11) << 22) & i;
      paramArrayOfint[b + 12] = (at(arrayOfByte, bool, 11) >>> 8 | at(arrayOfByte, bool, 12) << 24) & i;
      paramArrayOfint[b + 13] = (at(arrayOfByte, bool, 12) >>> 6 | at(arrayOfByte, bool, 13) << 26) & i;
      paramArrayOfint[b + 14] = (at(arrayOfByte, bool, 13) >>> 4 | at(arrayOfByte, bool, 14) << 28) & i;
      paramArrayOfint[b + 15] = at(arrayOfByte, bool, 14) >>> 2 & i;
      bool += true;
    } 
    System.arraycopy(paramArrayOfbyte2, 38400, paramArrayOfbyte1, paramInt, 32);
  }
  
  private static boolean testZ(long[] paramArrayOflong) {
    for (byte b = 0; b < 'ࠀ'; b++) {
      if (paramArrayOflong[b] < -2096250L || paramArrayOflong[b] > 2096250L)
        return true; 
    } 
    return false;
  }
  
  static void encodeSignature(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, long[] paramArrayOflong) {
    byte b1 = 0;
    for (byte b2 = 0; b2 < 'ր'; b2 += 11) {
      at(paramArrayOfbyte1, b2, 0, (int)(paramArrayOflong[b1 + 0] & 0x3FFFFFL | paramArrayOflong[b1 + 1] << 22L));
      at(paramArrayOfbyte1, b2, 1, (int)(paramArrayOflong[b1 + 1] >>> 10L & 0xFFFL | paramArrayOflong[b1 + 2] << 12L));
      at(paramArrayOfbyte1, b2, 2, (int)(paramArrayOflong[b1 + 2] >>> 20L & 0x3L | (paramArrayOflong[b1 + 3] & 0x3FFFFFL) << 2L | paramArrayOflong[b1 + 4] << 24L));
      at(paramArrayOfbyte1, b2, 3, (int)(paramArrayOflong[b1 + 4] >>> 8L & 0x3FFFL | paramArrayOflong[b1 + 5] << 14L));
      at(paramArrayOfbyte1, b2, 4, (int)(paramArrayOflong[b1 + 5] >>> 18L & 0xFL | (paramArrayOflong[b1 + 6] & 0x3FFFFFL) << 4L | paramArrayOflong[b1 + 7] << 26L));
      at(paramArrayOfbyte1, b2, 5, (int)(paramArrayOflong[b1 + 7] >>> 6L & 0xFFFFL | paramArrayOflong[b1 + 8] << 16L));
      at(paramArrayOfbyte1, b2, 6, (int)(paramArrayOflong[b1 + 8] >>> 16L & 0x3FL | (paramArrayOflong[b1 + 9] & 0x3FFFFFL) << 6L | paramArrayOflong[b1 + 10] << 28L));
      at(paramArrayOfbyte1, b2, 7, (int)(paramArrayOflong[b1 + 10] >>> 4L & 0x3FFFFL | paramArrayOflong[b1 + 11] << 18L));
      at(paramArrayOfbyte1, b2, 8, (int)(paramArrayOflong[b1 + 11] >>> 14L & 0xFFL | (paramArrayOflong[b1 + 12] & 0x3FFFFFL) << 8L | paramArrayOflong[b1 + 13] << 30L));
      at(paramArrayOfbyte1, b2, 9, (int)(paramArrayOflong[b1 + 13] >>> 2L & 0xFFFFFL | paramArrayOflong[b1 + 14] << 20L));
      at(paramArrayOfbyte1, b2, 10, (int)(paramArrayOflong[b1 + 14] >>> 12L & 0x3FFL | paramArrayOflong[b1 + 15] << 10L));
      b1 += 16;
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt2, paramArrayOfbyte1, paramInt1 + 5632, 32);
  }
  
  static void decodeSignature(byte[] paramArrayOfbyte1, long[] paramArrayOflong, byte[] paramArrayOfbyte2, int paramInt) {
    boolean bool = false;
    for (byte b = 0; b < 'ࠀ'; b += 16) {
      int i = at(paramArrayOfbyte2, bool, 0);
      int j = at(paramArrayOfbyte2, bool, 1);
      int k = at(paramArrayOfbyte2, bool, 2);
      int m = at(paramArrayOfbyte2, bool, 3);
      int n = at(paramArrayOfbyte2, bool, 4);
      int i1 = at(paramArrayOfbyte2, bool, 5);
      int i2 = at(paramArrayOfbyte2, bool, 6);
      int i3 = at(paramArrayOfbyte2, bool, 7);
      int i4 = at(paramArrayOfbyte2, bool, 8);
      int i5 = at(paramArrayOfbyte2, bool, 9);
      int i6 = at(paramArrayOfbyte2, bool, 10);
      paramArrayOflong[b] = (i << 10 >> 10);
      paramArrayOflong[b + 1] = (i >>> 22 | j << 20 >> 10);
      paramArrayOflong[b + 2] = (j >>> 12 | k << 30 >> 10);
      paramArrayOflong[b + 3] = (k << 8 >> 10);
      paramArrayOflong[b + 4] = (k >>> 24 | m << 18 >> 10);
      paramArrayOflong[b + 5] = (m >>> 14 | n << 28 >> 10);
      paramArrayOflong[b + 6] = (n << 6 >> 10);
      paramArrayOflong[b + 7] = (n >>> 26 | i1 << 16 >> 10);
      paramArrayOflong[b + 8] = (i1 >>> 16 | i2 << 26 >> 10);
      paramArrayOflong[b + 9] = (i2 << 4 >> 10);
      paramArrayOflong[b + 10] = (i2 >>> 28 | i3 << 14 >> 10);
      paramArrayOflong[b + 11] = (i3 >>> 18 | i4 << 24 >> 10);
      paramArrayOflong[b + 12] = (i4 << 2 >> 10);
      paramArrayOflong[b + 13] = (i4 >>> 30 | i5 << 12 >> 10);
      paramArrayOflong[b + 14] = (i5 >>> 20 | i6 << 22 >> 10);
      paramArrayOflong[b + 15] = (i6 >> 10);
      bool += true;
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt + 5632, paramArrayOfbyte1, 0, 32);
  }
  
  static void encodeC(int[] paramArrayOfint, short[] paramArrayOfshort, byte[] paramArrayOfbyte, int paramInt) {
    byte b1 = 0;
    short s = 0;
    short[] arrayOfShort = new short[2048];
    byte[] arrayOfByte = new byte[168];
    s = (short)(s + 1);
    HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(arrayOfByte, 0, 168, s, paramArrayOfbyte, paramInt, 32);
    Arrays.fill(arrayOfShort, (short)0);
    for (byte b2 = 0; b2 < 40; ) {
      if (b1 > '¥') {
        s = (short)(s + 1);
        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(arrayOfByte, 0, 168, s, paramArrayOfbyte, paramInt, 32);
        b1 = 0;
      } 
      int i = arrayOfByte[b1] << 8 | arrayOfByte[b1 + 1] & 0xFF;
      i &= 0x7FF;
      if (arrayOfShort[i] == 0) {
        if ((arrayOfByte[b1 + 2] & 0x1) == 1) {
          arrayOfShort[i] = -1;
        } else {
          arrayOfShort[i] = 1;
        } 
        paramArrayOfint[b2] = i;
        paramArrayOfshort[b2] = arrayOfShort[i];
        b2++;
      } 
      b1 += 3;
    } 
  }
  
  private static void hashFunction(byte[] paramArrayOfbyte1, int paramInt1, long[] paramArrayOflong, byte[] paramArrayOfbyte2, int paramInt2) {
    byte[] arrayOfByte = new byte[10320];
    for (byte b = 0; b < 5; b++) {
      int i = b * 2048;
      for (byte b1 = 0; b1 < 'ࠀ'; b1++) {
        int m = (int)paramArrayOflong[i];
        int j = 428072960 - m >> 31;
        m = m - 856145921 & j | m & (j ^ 0xFFFFFFFF);
        int k = m & 0xFFFFFF;
        j = 8388608 - k >> 31;
        k = k - 16777216 & j | k & (j ^ 0xFFFFFFFF);
        arrayOfByte[i++] = (byte)(m - k >> 24);
      } 
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt2, arrayOfByte, 10240, 80);
    HashUtils.secureHashAlgorithmKECCAK256(paramArrayOfbyte1, paramInt1, 32, arrayOfByte, 0, arrayOfByte.length);
  }
  
  static int lE24BitToInt(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    return i;
  }
  
  private static int NBLOCKS_SHAKE = 56;
  
  private static int BPLUS1BYTES = 3;
  
  static void sample_y(long[] paramArrayOflong, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte b = 0;
    int i = 0, j = 2048;
    byte[] arrayOfByte = new byte[2048 * BPLUS1BYTES + 1];
    int k = BPLUS1BYTES;
    short s = (short)(paramInt2 << 8);
    s = (short)(s + 1);
    HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(arrayOfByte, 0, 2048 * k, s, paramArrayOfbyte, paramInt1, 32);
    while (b < 'ࠀ') {
      if (i >= j * k) {
        j = NBLOCKS_SHAKE;
        s = (short)(s + 1);
        HashUtils.customizableSecureHashAlgorithmKECCAK256Simple(arrayOfByte, 0, 2048 * k, s, paramArrayOfbyte, paramInt1, 32);
        i = 0;
      } 
      paramArrayOflong[b] = (lE24BitToInt(arrayOfByte, i) & 0x3FFFFF);
      paramArrayOflong[b] = paramArrayOflong[b] - 2097151L;
      if (paramArrayOflong[b] != 2097152L)
        b++; 
      i += k;
    } 
  }
  
  private static void at(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3) {
    Pack.intToLittleEndian(paramInt3, paramArrayOfbyte, paramInt1 * 4 + paramInt2 * 4);
  }
  
  private static int at(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    int i = paramInt1 * 4 + paramInt2 * 4;
    int j = paramArrayOfbyte[i] & 0xFF;
    j |= (paramArrayOfbyte[++i] & 0xFF) << 8;
    j |= (paramArrayOfbyte[++i] & 0xFF) << 16;
    j |= paramArrayOfbyte[++i] << 24;
    return j;
  }
  
  static boolean test_correctness(long[] paramArrayOflong, int paramInt) {
    for (byte b = 0; b < 'ࠀ'; b++) {
      int i = (int)(428072960L - paramArrayOflong[paramInt + b]) >> 31;
      int k = (int)(paramArrayOflong[paramInt + b] - 856145921L & i | paramArrayOflong[paramInt + b] & (i ^ 0xFFFFFFFF));
      int m = (absolute(k) - 428072059 ^ 0xFFFFFFFF) >>> 31;
      int j = k;
      k = k + 8388608 - 1 >> 24;
      k = j - (k << 24);
      int n = (absolute(k) - 8387707 ^ 0xFFFFFFFF) >>> 31;
      if ((m | n) == 1)
        return true; 
    } 
    return false;
  }
  
  private static boolean testRejection(long[] paramArrayOflong) {
    int i = 0;
    for (byte b = 0; b < 'ࠀ'; b++)
      i = (int)(i | 2096250L - absolute(paramArrayOflong[b])); 
    return (i >>> 31 > 0);
  }
  
  private static int absolute(int paramInt) {
    return (paramInt >> 31 ^ paramInt) - (paramInt >> 31);
  }
  
  private static long absolute(long paramLong) {
    return (paramLong >> 63L ^ paramLong) - (paramLong >> 63L);
  }
  
  private static boolean checkPolynomial(long[] paramArrayOflong, int paramInt1, int paramInt2) {
    int i = 0;
    char c = 'ࠀ';
    long[] arrayOfLong = new long[2048];
    byte b;
    for (b = 0; b < 'ࠀ'; b++)
      arrayOfLong[b] = absolute((int)paramArrayOflong[paramInt1 + b]); 
    for (b = 0; b < 40; b++) {
      for (byte b1 = 0; b1 < c - 1; b1++) {
        long l2 = arrayOfLong[b1 + 1] - arrayOfLong[b1] >> 31L;
        long l1 = arrayOfLong[b1 + 1] & l2 | arrayOfLong[b1] & (l2 ^ 0xFFFFFFFFFFFFFFFFL);
        arrayOfLong[b1 + 1] = arrayOfLong[b1] & l2 | arrayOfLong[b1 + 1] & (l2 ^ 0xFFFFFFFFFFFFFFFFL);
        arrayOfLong[b1] = l1;
      } 
      i += (int)arrayOfLong[c - 1];
      c--;
    } 
    return (i > paramInt2);
  }
  
  static boolean memoryEqual(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, int paramInt3) {
    if (paramInt1 + paramInt3 <= paramArrayOfbyte1.length && paramInt2 + paramInt3 <= paramArrayOfbyte2.length) {
      for (byte b = 0; b < paramInt3; b++) {
        if (paramArrayOfbyte1[paramInt1 + b] != paramArrayOfbyte2[paramInt2 + b])
          return false; 
      } 
      return true;
    } 
    return false;
  }
}
