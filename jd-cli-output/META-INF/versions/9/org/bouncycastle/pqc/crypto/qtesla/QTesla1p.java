package META-INF.versions.9.org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.qtesla.HashUtils;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class QTesla1p {
  private static final int PARAM_N = 1024;
  
  private static final int PARAM_Q = 343576577;
  
  private static final int PARAM_Q_LOG = 29;
  
  private static final long PARAM_QINV = 2205847551L;
  
  private static final int PARAM_BARR_MULT = 3;
  
  private static final int PARAM_BARR_DIV = 30;
  
  private static final int PARAM_B = 524287;
  
  private static final int PARAM_B_BITS = 19;
  
  private static final int PARAM_S_BITS = 8;
  
  private static final int PARAM_K = 4;
  
  private static final int PARAM_H = 25;
  
  private static final int PARAM_D = 22;
  
  private static final int PARAM_GEN_A = 108;
  
  private static final int PARAM_KEYGEN_BOUND_E = 554;
  
  private static final int PARAM_E = 554;
  
  private static final int PARAM_KEYGEN_BOUND_S = 554;
  
  private static final int PARAM_S = 554;
  
  private static final int PARAM_R2_INVN = 13632409;
  
  private static final int CRYPTO_RANDOMBYTES = 32;
  
  private static final int CRYPTO_SEEDBYTES = 32;
  
  private static final int CRYPTO_C_BYTES = 32;
  
  private static final int HM_BYTES = 40;
  
  private static final int RADIX32 = 32;
  
  static final int CRYPTO_BYTES = 2592;
  
  static final int CRYPTO_SECRETKEYBYTES = 5224;
  
  static final int CRYPTO_PUBLICKEYBYTES = 14880;
  
  private static final int maskb1 = 1048575;
  
  static int generateKeyPair(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, SecureRandom paramSecureRandom) {
    byte b1 = 0;
    byte[] arrayOfByte1 = new byte[32];
    byte[] arrayOfByte2 = new byte[224];
    int[] arrayOfInt1 = new int[1024];
    int[] arrayOfInt2 = new int[4096];
    int[] arrayOfInt3 = new int[4096];
    int[] arrayOfInt4 = new int[4096];
    int[] arrayOfInt5 = new int[1024];
    paramSecureRandom.nextBytes(arrayOfByte1);
    HashUtils.secureHashAlgorithmKECCAK128(arrayOfByte2, 0, 224, arrayOfByte1, 0, 32);
    byte b2;
    for (b2 = 0; b2 < 4;) {
      while (true) {
        Gaussian.sample_gauss_poly(++b1, arrayOfByte2, b2 * 32, arrayOfInt2, b2 * 1024);
        if (!checkPolynomial(arrayOfInt2, b2 * 1024, 554))
          b2++; 
      } 
    } 
    do {
      Gaussian.sample_gauss_poly(++b1, arrayOfByte2, 128, arrayOfInt1, 0);
    } while (checkPolynomial(arrayOfInt1, 0, 554));
    QTesla1PPolynomial.poly_uniform(arrayOfInt3, arrayOfByte2, 160);
    QTesla1PPolynomial.poly_ntt(arrayOfInt5, arrayOfInt1);
    for (b2 = 0; b2 < 4; b2++) {
      QTesla1PPolynomial.poly_mul(arrayOfInt4, b2 * 1024, arrayOfInt3, b2 * 1024, arrayOfInt5);
      QTesla1PPolynomial.poly_add_correct(arrayOfInt4, b2 * 1024, arrayOfInt4, b2 * 1024, arrayOfInt2, b2 * 1024);
    } 
    encodePublicKey(paramArrayOfbyte1, arrayOfInt4, arrayOfByte2, 160);
    encodePrivateKey(paramArrayOfbyte2, arrayOfInt1, arrayOfInt2, arrayOfByte2, 160, paramArrayOfbyte1);
    return 0;
  }
  
  static int generateSignature(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2, byte[] paramArrayOfbyte3, SecureRandom paramSecureRandom) {
    byte[] arrayOfByte1 = new byte[32];
    byte[] arrayOfByte2 = new byte[32];
    byte[] arrayOfByte3 = new byte[144];
    int[] arrayOfInt1 = new int[25];
    short[] arrayOfShort = new short[25];
    int[] arrayOfInt2 = new int[1024];
    int[] arrayOfInt3 = new int[1024];
    int[] arrayOfInt4 = new int[1024];
    int[] arrayOfInt5 = new int[1024];
    int[] arrayOfInt6 = new int[4096];
    int[] arrayOfInt7 = new int[4096];
    int[] arrayOfInt8 = new int[4096];
    byte b = 0;
    boolean bool = false;
    System.arraycopy(paramArrayOfbyte3, 5152, arrayOfByte3, 0, 32);
    byte[] arrayOfByte4 = new byte[32];
    paramSecureRandom.nextBytes(arrayOfByte4);
    System.arraycopy(arrayOfByte4, 0, arrayOfByte3, 32, 32);
    HashUtils.secureHashAlgorithmKECCAK128(arrayOfByte3, 64, 40, paramArrayOfbyte2, 0, paramInt2);
    HashUtils.secureHashAlgorithmKECCAK128(arrayOfByte2, 0, 32, arrayOfByte3, 0, arrayOfByte3.length - 40);
    System.arraycopy(paramArrayOfbyte3, 5184, arrayOfByte3, arrayOfByte3.length - 40, 40);
    QTesla1PPolynomial.poly_uniform(arrayOfInt8, paramArrayOfbyte3, 5120);
    while (true) {
      sample_y(arrayOfInt2, arrayOfByte2, 0, ++b);
      QTesla1PPolynomial.poly_ntt(arrayOfInt3, arrayOfInt2);
      byte b1;
      for (b1 = 0; b1 < 4; b1++)
        QTesla1PPolynomial.poly_mul(arrayOfInt6, b1 * 1024, arrayOfInt8, b1 * 1024, arrayOfInt3); 
      hashFunction(arrayOfByte1, 0, arrayOfInt6, arrayOfByte3, 64);
      encodeC(arrayOfInt1, arrayOfShort, arrayOfByte1, 0);
      QTesla1PPolynomial.sparse_mul8(arrayOfInt4, 0, paramArrayOfbyte3, 0, arrayOfInt1, arrayOfShort);
      QTesla1PPolynomial.poly_add(arrayOfInt5, arrayOfInt2, arrayOfInt4);
      if (testRejection(arrayOfInt5))
        continue; 
      for (b1 = 0; b1 < 4; b1++) {
        QTesla1PPolynomial.sparse_mul8(arrayOfInt7, b1 * 1024, paramArrayOfbyte3, 1024 * (b1 + 1), arrayOfInt1, arrayOfShort);
        QTesla1PPolynomial.poly_sub(arrayOfInt6, b1 * 1024, arrayOfInt6, b1 * 1024, arrayOfInt7, b1 * 1024);
        bool = test_correctness(arrayOfInt6, b1 * 1024);
        if (bool)
          break; 
      } 
      if (bool)
        continue; 
      break;
    } 
    encodeSignature(paramArrayOfbyte1, 0, arrayOfByte1, 0, arrayOfInt5);
    return 0;
  }
  
  static int verifying(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2, byte[] paramArrayOfbyte3) {
    byte[] arrayOfByte1 = new byte[32];
    byte[] arrayOfByte2 = new byte[32];
    byte[] arrayOfByte3 = new byte[32];
    byte[] arrayOfByte4 = new byte[80];
    int[] arrayOfInt1 = new int[25];
    short[] arrayOfShort = new short[25];
    int[] arrayOfInt2 = new int[4096];
    int[] arrayOfInt3 = new int[4096];
    int[] arrayOfInt4 = new int[4096];
    int[] arrayOfInt5 = new int[4096];
    int[] arrayOfInt6 = new int[1024];
    int[] arrayOfInt7 = new int[1024];
    byte b = 0;
    if (paramInt2 != 2592)
      return -1; 
    decodeSignature(arrayOfByte1, arrayOfInt6, paramArrayOfbyte2, paramInt1);
    if (testZ(arrayOfInt6))
      return -2; 
    decodePublicKey(arrayOfInt2, arrayOfByte3, 0, paramArrayOfbyte3);
    HashUtils.secureHashAlgorithmKECCAK128(arrayOfByte4, 0, 40, paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
    HashUtils.secureHashAlgorithmKECCAK128(arrayOfByte4, 40, 40, paramArrayOfbyte3, 0, 14848);
    QTesla1PPolynomial.poly_uniform(arrayOfInt4, arrayOfByte3, 0);
    encodeC(arrayOfInt1, arrayOfShort, arrayOfByte1, 0);
    QTesla1PPolynomial.poly_ntt(arrayOfInt7, arrayOfInt6);
    for (b = 0; b < 4; b++) {
      QTesla1PPolynomial.sparse_mul32(arrayOfInt5, b * 1024, arrayOfInt2, b * 1024, arrayOfInt1, arrayOfShort);
      QTesla1PPolynomial.poly_mul(arrayOfInt3, b * 1024, arrayOfInt4, b * 1024, arrayOfInt7);
      QTesla1PPolynomial.poly_sub_reduce(arrayOfInt3, b * 1024, arrayOfInt3, b * 1024, arrayOfInt5, b * 1024);
    } 
    hashFunction(arrayOfByte2, 0, arrayOfInt3, arrayOfByte4, 0);
    if (!memoryEqual(arrayOfByte1, 0, arrayOfByte2, 0, 32))
      return -3; 
    return 0;
  }
  
  static void encodePrivateKey(byte[] paramArrayOfbyte1, int[] paramArrayOfint1, int[] paramArrayOfint2, byte[] paramArrayOfbyte2, int paramInt, byte[] paramArrayOfbyte3) {
    byte b2 = 0;
    byte b3 = 0;
    byte b1;
    for (b1 = 0; b1 < 'Ѐ'; b1++)
      paramArrayOfbyte1[b3 + b1] = (byte)paramArrayOfint1[b1]; 
    b3 += 1024;
    for (b2 = 0; b2 < 4; b2++) {
      for (b1 = 0; b1 < 'Ѐ'; b1++)
        paramArrayOfbyte1[b3 + b2 * 1024 + b1] = (byte)paramArrayOfint2[b2 * 1024 + b1]; 
    } 
    b3 += 4096;
    System.arraycopy(paramArrayOfbyte2, paramInt, paramArrayOfbyte1, b3, 64);
    b3 += 64;
    HashUtils.secureHashAlgorithmKECCAK128(paramArrayOfbyte1, b3, 40, paramArrayOfbyte3, 0, 14848);
    b3 += 40;
  }
  
  static void encodePublicKey(byte[] paramArrayOfbyte1, int[] paramArrayOfint, byte[] paramArrayOfbyte2, int paramInt) {
    byte b1 = 0;
    for (byte b2 = 0; b2 < '຀'; b2 += 29) {
      at(paramArrayOfbyte1, b2, 0, paramArrayOfint[b1] | paramArrayOfint[b1 + 1] << 29);
      at(paramArrayOfbyte1, b2, 1, paramArrayOfint[b1 + 1] >> 3 | paramArrayOfint[b1 + 2] << 26);
      at(paramArrayOfbyte1, b2, 2, paramArrayOfint[b1 + 2] >> 6 | paramArrayOfint[b1 + 3] << 23);
      at(paramArrayOfbyte1, b2, 3, paramArrayOfint[b1 + 3] >> 9 | paramArrayOfint[b1 + 4] << 20);
      at(paramArrayOfbyte1, b2, 4, paramArrayOfint[b1 + 4] >> 12 | paramArrayOfint[b1 + 5] << 17);
      at(paramArrayOfbyte1, b2, 5, paramArrayOfint[b1 + 5] >> 15 | paramArrayOfint[b1 + 6] << 14);
      at(paramArrayOfbyte1, b2, 6, paramArrayOfint[b1 + 6] >> 18 | paramArrayOfint[b1 + 7] << 11);
      at(paramArrayOfbyte1, b2, 7, paramArrayOfint[b1 + 7] >> 21 | paramArrayOfint[b1 + 8] << 8);
      at(paramArrayOfbyte1, b2, 8, paramArrayOfint[b1 + 8] >> 24 | paramArrayOfint[b1 + 9] << 5);
      at(paramArrayOfbyte1, b2, 9, paramArrayOfint[b1 + 9] >> 27 | paramArrayOfint[b1 + 10] << 2 | paramArrayOfint[b1 + 11] << 31);
      at(paramArrayOfbyte1, b2, 10, paramArrayOfint[b1 + 11] >> 1 | paramArrayOfint[b1 + 12] << 28);
      at(paramArrayOfbyte1, b2, 11, paramArrayOfint[b1 + 12] >> 4 | paramArrayOfint[b1 + 13] << 25);
      at(paramArrayOfbyte1, b2, 12, paramArrayOfint[b1 + 13] >> 7 | paramArrayOfint[b1 + 14] << 22);
      at(paramArrayOfbyte1, b2, 13, paramArrayOfint[b1 + 14] >> 10 | paramArrayOfint[b1 + 15] << 19);
      at(paramArrayOfbyte1, b2, 14, paramArrayOfint[b1 + 15] >> 13 | paramArrayOfint[b1 + 16] << 16);
      at(paramArrayOfbyte1, b2, 15, paramArrayOfint[b1 + 16] >> 16 | paramArrayOfint[b1 + 17] << 13);
      at(paramArrayOfbyte1, b2, 16, paramArrayOfint[b1 + 17] >> 19 | paramArrayOfint[b1 + 18] << 10);
      at(paramArrayOfbyte1, b2, 17, paramArrayOfint[b1 + 18] >> 22 | paramArrayOfint[b1 + 19] << 7);
      at(paramArrayOfbyte1, b2, 18, paramArrayOfint[b1 + 19] >> 25 | paramArrayOfint[b1 + 20] << 4);
      at(paramArrayOfbyte1, b2, 19, paramArrayOfint[b1 + 20] >> 28 | paramArrayOfint[b1 + 21] << 1 | paramArrayOfint[b1 + 22] << 30);
      at(paramArrayOfbyte1, b2, 20, paramArrayOfint[b1 + 22] >> 2 | paramArrayOfint[b1 + 23] << 27);
      at(paramArrayOfbyte1, b2, 21, paramArrayOfint[b1 + 23] >> 5 | paramArrayOfint[b1 + 24] << 24);
      at(paramArrayOfbyte1, b2, 22, paramArrayOfint[b1 + 24] >> 8 | paramArrayOfint[b1 + 25] << 21);
      at(paramArrayOfbyte1, b2, 23, paramArrayOfint[b1 + 25] >> 11 | paramArrayOfint[b1 + 26] << 18);
      at(paramArrayOfbyte1, b2, 24, paramArrayOfint[b1 + 26] >> 14 | paramArrayOfint[b1 + 27] << 15);
      at(paramArrayOfbyte1, b2, 25, paramArrayOfint[b1 + 27] >> 17 | paramArrayOfint[b1 + 28] << 12);
      at(paramArrayOfbyte1, b2, 26, paramArrayOfint[b1 + 28] >> 20 | paramArrayOfint[b1 + 29] << 9);
      at(paramArrayOfbyte1, b2, 27, paramArrayOfint[b1 + 29] >> 23 | paramArrayOfint[b1 + 30] << 6);
      at(paramArrayOfbyte1, b2, 28, paramArrayOfint[b1 + 30] >> 26 | paramArrayOfint[b1 + 31] << 3);
      b1 += 32;
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt, paramArrayOfbyte1, 14848, 32);
  }
  
  static void decodePublicKey(int[] paramArrayOfint, byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2) {
    boolean bool = false;
    byte[] arrayOfByte = paramArrayOfbyte2;
    int i = 536870911;
    for (byte b = 0; b < 'က'; b += 32) {
      paramArrayOfint[b] = at(arrayOfByte, bool, 0) & i;
      paramArrayOfint[b + 1] = (at(arrayOfByte, bool, 0) >>> 29 | at(arrayOfByte, bool, 1) << 3) & i;
      paramArrayOfint[b + 2] = (at(arrayOfByte, bool, 1) >>> 26 | at(arrayOfByte, bool, 2) << 6) & i;
      paramArrayOfint[b + 3] = (at(arrayOfByte, bool, 2) >>> 23 | at(arrayOfByte, bool, 3) << 9) & i;
      paramArrayOfint[b + 4] = (at(arrayOfByte, bool, 3) >>> 20 | at(arrayOfByte, bool, 4) << 12) & i;
      paramArrayOfint[b + 5] = (at(arrayOfByte, bool, 4) >>> 17 | at(arrayOfByte, bool, 5) << 15) & i;
      paramArrayOfint[b + 6] = (at(arrayOfByte, bool, 5) >>> 14 | at(arrayOfByte, bool, 6) << 18) & i;
      paramArrayOfint[b + 7] = (at(arrayOfByte, bool, 6) >>> 11 | at(arrayOfByte, bool, 7) << 21) & i;
      paramArrayOfint[b + 8] = (at(arrayOfByte, bool, 7) >>> 8 | at(arrayOfByte, bool, 8) << 24) & i;
      paramArrayOfint[b + 9] = (at(arrayOfByte, bool, 8) >>> 5 | at(arrayOfByte, bool, 9) << 27) & i;
      paramArrayOfint[b + 10] = at(arrayOfByte, bool, 9) >>> 2 & i;
      paramArrayOfint[b + 11] = (at(arrayOfByte, bool, 9) >>> 31 | at(arrayOfByte, bool, 10) << 1) & i;
      paramArrayOfint[b + 12] = (at(arrayOfByte, bool, 10) >>> 28 | at(arrayOfByte, bool, 11) << 4) & i;
      paramArrayOfint[b + 13] = (at(arrayOfByte, bool, 11) >>> 25 | at(arrayOfByte, bool, 12) << 7) & i;
      paramArrayOfint[b + 14] = (at(arrayOfByte, bool, 12) >>> 22 | at(arrayOfByte, bool, 13) << 10) & i;
      paramArrayOfint[b + 15] = (at(arrayOfByte, bool, 13) >>> 19 | at(arrayOfByte, bool, 14) << 13) & i;
      paramArrayOfint[b + 16] = (at(arrayOfByte, bool, 14) >>> 16 | at(arrayOfByte, bool, 15) << 16) & i;
      paramArrayOfint[b + 17] = (at(arrayOfByte, bool, 15) >>> 13 | at(arrayOfByte, bool, 16) << 19) & i;
      paramArrayOfint[b + 18] = (at(arrayOfByte, bool, 16) >>> 10 | at(arrayOfByte, bool, 17) << 22) & i;
      paramArrayOfint[b + 19] = (at(arrayOfByte, bool, 17) >>> 7 | at(arrayOfByte, bool, 18) << 25) & i;
      paramArrayOfint[b + 20] = (at(arrayOfByte, bool, 18) >>> 4 | at(arrayOfByte, bool, 19) << 28) & i;
      paramArrayOfint[b + 21] = at(arrayOfByte, bool, 19) >>> 1 & i;
      paramArrayOfint[b + 22] = (at(arrayOfByte, bool, 19) >>> 30 | at(arrayOfByte, bool, 20) << 2) & i;
      paramArrayOfint[b + 23] = (at(arrayOfByte, bool, 20) >>> 27 | at(arrayOfByte, bool, 21) << 5) & i;
      paramArrayOfint[b + 24] = (at(arrayOfByte, bool, 21) >>> 24 | at(arrayOfByte, bool, 22) << 8) & i;
      paramArrayOfint[b + 25] = (at(arrayOfByte, bool, 22) >>> 21 | at(arrayOfByte, bool, 23) << 11) & i;
      paramArrayOfint[b + 26] = (at(arrayOfByte, bool, 23) >>> 18 | at(arrayOfByte, bool, 24) << 14) & i;
      paramArrayOfint[b + 27] = (at(arrayOfByte, bool, 24) >>> 15 | at(arrayOfByte, bool, 25) << 17) & i;
      paramArrayOfint[b + 28] = (at(arrayOfByte, bool, 25) >>> 12 | at(arrayOfByte, bool, 26) << 20) & i;
      paramArrayOfint[b + 29] = (at(arrayOfByte, bool, 26) >>> 9 | at(arrayOfByte, bool, 27) << 23) & i;
      paramArrayOfint[b + 30] = (at(arrayOfByte, bool, 27) >>> 6 | at(arrayOfByte, bool, 28) << 26) & i;
      paramArrayOfint[b + 31] = at(arrayOfByte, bool, 28) >>> 3;
      bool += true;
    } 
    System.arraycopy(paramArrayOfbyte2, 14848, paramArrayOfbyte1, paramInt, 32);
  }
  
  private static boolean testZ(int[] paramArrayOfint) {
    for (byte b = 0; b < 'Ѐ'; b++) {
      if (paramArrayOfint[b] < -523733 || paramArrayOfint[b] > 523733)
        return true; 
    } 
    return false;
  }
  
  static void encodeSignature(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, int[] paramArrayOfint) {
    byte b1 = 0;
    for (byte b2 = 0; b2 < 'ʀ'; b2 += 10) {
      at(paramArrayOfbyte1, b2, 0, paramArrayOfint[b1] & 0xFFFFF | paramArrayOfint[b1 + 1] << 20);
      at(paramArrayOfbyte1, b2, 1, paramArrayOfint[b1 + 1] >>> 12 & 0xFF | (paramArrayOfint[b1 + 2] & 0xFFFFF) << 8 | paramArrayOfint[b1 + 3] << 28);
      at(paramArrayOfbyte1, b2, 2, paramArrayOfint[b1 + 3] >>> 4 & 0xFFFF | paramArrayOfint[b1 + 4] << 16);
      at(paramArrayOfbyte1, b2, 3, paramArrayOfint[b1 + 4] >>> 16 & 0xF | (paramArrayOfint[b1 + 5] & 0xFFFFF) << 4 | paramArrayOfint[b1 + 6] << 24);
      at(paramArrayOfbyte1, b2, 4, paramArrayOfint[b1 + 6] >>> 8 & 0xFFF | paramArrayOfint[b1 + 7] << 12);
      at(paramArrayOfbyte1, b2, 5, paramArrayOfint[b1 + 8] & 0xFFFFF | paramArrayOfint[b1 + 9] << 20);
      at(paramArrayOfbyte1, b2, 6, paramArrayOfint[b1 + 9] >>> 12 & 0xFF | (paramArrayOfint[b1 + 10] & 0xFFFFF) << 8 | paramArrayOfint[b1 + 11] << 28);
      at(paramArrayOfbyte1, b2, 7, paramArrayOfint[b1 + 11] >>> 4 & 0xFFFF | paramArrayOfint[b1 + 12] << 16);
      at(paramArrayOfbyte1, b2, 8, paramArrayOfint[b1 + 12] >>> 16 & 0xF | (paramArrayOfint[b1 + 13] & 0xFFFFF) << 4 | paramArrayOfint[b1 + 14] << 24);
      at(paramArrayOfbyte1, b2, 9, paramArrayOfint[b1 + 14] >>> 8 & 0xFFF | paramArrayOfint[b1 + 15] << 12);
      b1 += 16;
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt2, paramArrayOfbyte1, paramInt1 + 2560, 32);
  }
  
  static void decodeSignature(byte[] paramArrayOfbyte1, int[] paramArrayOfint, byte[] paramArrayOfbyte2, int paramInt) {
    boolean bool = false;
    for (byte b = 0; b < 'Ѐ'; b += 16) {
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
      paramArrayOfint[b] = i << 12 >> 12;
      paramArrayOfint[b + 1] = i >>> 20 | j << 24 >> 12;
      paramArrayOfint[b + 2] = j << 4 >> 12;
      paramArrayOfint[b + 3] = j >>> 28 | k << 16 >> 12;
      paramArrayOfint[b + 4] = k >>> 16 | m << 28 >> 12;
      paramArrayOfint[b + 5] = m << 8 >> 12;
      paramArrayOfint[b + 6] = m >>> 24 | n << 20 >> 12;
      paramArrayOfint[b + 7] = n >> 12;
      paramArrayOfint[b + 8] = i1 << 12 >> 12;
      paramArrayOfint[b + 9] = i1 >>> 20 | i2 << 24 >> 12;
      paramArrayOfint[b + 10] = i2 << 4 >> 12;
      paramArrayOfint[b + 11] = i2 >>> 28 | i3 << 16 >> 12;
      paramArrayOfint[b + 12] = i3 >>> 16 | i4 << 28 >> 12;
      paramArrayOfint[b + 13] = i4 << 8 >> 12;
      paramArrayOfint[b + 14] = i4 >>> 24 | i5 << 20 >> 12;
      paramArrayOfint[b + 15] = i5 >> 12;
      bool += true;
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt + 2560, paramArrayOfbyte1, 0, 32);
  }
  
  static void encodeC(int[] paramArrayOfint, short[] paramArrayOfshort, byte[] paramArrayOfbyte, int paramInt) {
    byte b1 = 0;
    short s = 0;
    short[] arrayOfShort = new short[1024];
    byte[] arrayOfByte = new byte[168];
    s = (short)(s + 1);
    HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(arrayOfByte, 0, 168, s, paramArrayOfbyte, paramInt, 32);
    Arrays.fill(arrayOfShort, (short)0);
    for (byte b2 = 0; b2 < 25; ) {
      if (b1 > '¥') {
        s = (short)(s + 1);
        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(arrayOfByte, 0, 168, s, paramArrayOfbyte, paramInt, 32);
        b1 = 0;
      } 
      int i = arrayOfByte[b1] << 8 | arrayOfByte[b1 + 1] & 0xFF;
      i &= 0x3FF;
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
  
  private static void hashFunction(byte[] paramArrayOfbyte1, int paramInt1, int[] paramArrayOfint, byte[] paramArrayOfbyte2, int paramInt2) {
    byte[] arrayOfByte = new byte[4176];
    for (byte b = 0; b < 4; b++) {
      int i = b * 1024;
      for (byte b1 = 0; b1 < 'Ѐ'; b1++) {
        int m = paramArrayOfint[i];
        int j = 171788288 - m >> 31;
        m = m - 343576577 & j | m & (j ^ 0xFFFFFFFF);
        int k = m & 0x3FFFFF;
        j = 2097152 - k >> 31;
        k = k - 4194304 & j | k & (j ^ 0xFFFFFFFF);
        arrayOfByte[i++] = (byte)(m - k >> 22);
      } 
    } 
    System.arraycopy(paramArrayOfbyte2, paramInt2, arrayOfByte, 4096, 80);
    HashUtils.secureHashAlgorithmKECCAK128(paramArrayOfbyte1, paramInt1, 32, arrayOfByte, 0, arrayOfByte.length);
  }
  
  static int littleEndianToInt24(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    return i;
  }
  
  private static int NBLOCKS_SHAKE = 56;
  
  private static int BPLUS1BYTES = 3;
  
  static void sample_y(int[] paramArrayOfint, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte b = 0;
    int i = 0, j = 1024;
    byte[] arrayOfByte = new byte[1024 * BPLUS1BYTES + 1];
    int k = BPLUS1BYTES;
    short s = (short)(paramInt2 << 8);
    s = (short)(s + 1);
    HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(arrayOfByte, 0, 1024 * k, s, paramArrayOfbyte, paramInt1, 32);
    while (b < 'Ѐ') {
      if (i >= j * k) {
        j = NBLOCKS_SHAKE;
        s = (short)(s + 1);
        HashUtils.customizableSecureHashAlgorithmKECCAK128Simple(arrayOfByte, 0, 1024 * k, s, paramArrayOfbyte, paramInt1, 32);
        i = 0;
      } 
      paramArrayOfint[b] = littleEndianToInt24(arrayOfByte, i) & 0xFFFFF;
      paramArrayOfint[b] = paramArrayOfint[b] - 524287;
      if (paramArrayOfint[b] != 524288)
        b++; 
      i += k;
    } 
  }
  
  private static void at(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3) {
    Pack.intToLittleEndian(paramInt3, paramArrayOfbyte, paramInt1 + paramInt2 << 2);
  }
  
  private static int at(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    return Pack.littleEndianToInt(paramArrayOfbyte, paramInt1 + paramInt2 << 2);
  }
  
  static boolean test_correctness(int[] paramArrayOfint, int paramInt) {
    for (byte b = 0; b < 'Ѐ'; b++) {
      int i1 = paramArrayOfint[paramInt + b];
      int i = 171788288 - i1 >> 31;
      int k = i1 - 343576577 & i | i1 & (i ^ 0xFFFFFFFF);
      int m = (absolute(k) - 171787734 ^ 0xFFFFFFFF) >>> 31;
      int j = k;
      k = k + 2097152 - 1 >> 22;
      k = j - (k << 22);
      int n = (absolute(k) - 2096598 ^ 0xFFFFFFFF) >>> 31;
      if ((m | n) == 1)
        return true; 
    } 
    return false;
  }
  
  private static boolean testRejection(int[] paramArrayOfint) {
    int i = 0;
    for (byte b = 0; b < 'Ѐ'; b++)
      i |= 523733 - absolute(paramArrayOfint[b]); 
    return (i >>> 31 != 0);
  }
  
  private static int absolute(int paramInt) {
    int i = paramInt >> 31;
    return (i ^ paramInt) - i;
  }
  
  private static boolean checkPolynomial(int[] paramArrayOfint, int paramInt1, int paramInt2) {
    int i = 0;
    char c = 'Ѐ';
    int[] arrayOfInt = new int[1024];
    byte b;
    for (b = 0; b < 'Ѐ'; b++)
      arrayOfInt[b] = absolute(paramArrayOfint[paramInt1 + b]); 
    for (b = 0; b < 25; b++) {
      for (byte b1 = 0; b1 < c - 1; b1++) {
        int m = arrayOfInt[b1], n = arrayOfInt[b1 + 1];
        int k = n - m >> 31;
        int j = n & k | m & (k ^ 0xFFFFFFFF);
        arrayOfInt[b1 + 1] = m & k | n & (k ^ 0xFFFFFFFF);
        arrayOfInt[b1] = j;
      } 
      i += arrayOfInt[c - 1];
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
