package org.bouncycastle.math.ec.rfc7748;

import java.security.SecureRandom;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

public abstract class X448 {
  public static final int POINT_SIZE = 56;
  
  public static final int SCALAR_SIZE = 56;
  
  private static final int C_A = 156326;
  
  private static final int C_A24 = 39082;
  
  public static boolean calculateAgreement(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, int paramInt3) {
    scalarMult(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, paramInt3);
    return !Arrays.areAllZeroes(paramArrayOfbyte3, paramInt3, 56);
  }
  
  private static int decode32(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    i |= paramArrayOfbyte[++paramInt] << 24;
    return i;
  }
  
  private static void decodeScalar(byte[] paramArrayOfbyte, int paramInt, int[] paramArrayOfint) {
    for (byte b = 0; b < 14; b++)
      paramArrayOfint[b] = decode32(paramArrayOfbyte, paramInt + b * 4); 
    paramArrayOfint[0] = paramArrayOfint[0] & 0xFFFFFFFC;
    paramArrayOfint[13] = paramArrayOfint[13] | Integer.MIN_VALUE;
  }
  
  public static void generatePrivateKey(SecureRandom paramSecureRandom, byte[] paramArrayOfbyte) {
    paramSecureRandom.nextBytes(paramArrayOfbyte);
    paramArrayOfbyte[0] = (byte)(paramArrayOfbyte[0] & 0xFC);
    paramArrayOfbyte[55] = (byte)(paramArrayOfbyte[55] | 0x80);
  }
  
  public static void generatePublicKey(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    scalarMultBase(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2);
  }
  
  private static void pointDouble(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    F.add(paramArrayOfint1, paramArrayOfint2, arrayOfInt1);
    F.sub(paramArrayOfint1, paramArrayOfint2, arrayOfInt2);
    F.sqr(arrayOfInt1, arrayOfInt1);
    F.sqr(arrayOfInt2, arrayOfInt2);
    F.mul(arrayOfInt1, arrayOfInt2, paramArrayOfint1);
    F.sub(arrayOfInt1, arrayOfInt2, arrayOfInt1);
    F.mul(arrayOfInt1, 39082, paramArrayOfint2);
    F.add(paramArrayOfint2, arrayOfInt2, paramArrayOfint2);
    F.mul(paramArrayOfint2, arrayOfInt1, paramArrayOfint2);
  }
  
  public static void precompute() {
    Ed448.precompute();
  }
  
  public static void scalarMult(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, int paramInt3) {
    int[] arrayOfInt1 = new int[14];
    decodeScalar(paramArrayOfbyte1, paramInt1, arrayOfInt1);
    int[] arrayOfInt2 = F.create();
    F.decode(paramArrayOfbyte2, paramInt2, arrayOfInt2);
    int[] arrayOfInt3 = F.create();
    F.copy(arrayOfInt2, 0, arrayOfInt3, 0);
    int[] arrayOfInt4 = F.create();
    arrayOfInt4[0] = 1;
    int[] arrayOfInt5 = F.create();
    arrayOfInt5[0] = 1;
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = F.create();
    int[] arrayOfInt8 = F.create();
    char c = 'ƿ';
    int i = 1;
    while (true) {
      F.add(arrayOfInt5, arrayOfInt6, arrayOfInt7);
      F.sub(arrayOfInt5, arrayOfInt6, arrayOfInt5);
      F.add(arrayOfInt3, arrayOfInt4, arrayOfInt6);
      F.sub(arrayOfInt3, arrayOfInt4, arrayOfInt3);
      F.mul(arrayOfInt7, arrayOfInt3, arrayOfInt7);
      F.mul(arrayOfInt5, arrayOfInt6, arrayOfInt5);
      F.sqr(arrayOfInt6, arrayOfInt6);
      F.sqr(arrayOfInt3, arrayOfInt3);
      F.sub(arrayOfInt6, arrayOfInt3, arrayOfInt8);
      F.mul(arrayOfInt8, 39082, arrayOfInt4);
      F.add(arrayOfInt4, arrayOfInt3, arrayOfInt4);
      F.mul(arrayOfInt4, arrayOfInt8, arrayOfInt4);
      F.mul(arrayOfInt3, arrayOfInt6, arrayOfInt3);
      F.sub(arrayOfInt7, arrayOfInt5, arrayOfInt6);
      F.add(arrayOfInt7, arrayOfInt5, arrayOfInt5);
      F.sqr(arrayOfInt5, arrayOfInt5);
      F.sqr(arrayOfInt6, arrayOfInt6);
      F.mul(arrayOfInt6, arrayOfInt2, arrayOfInt6);
      int j = --c >>> 5;
      int k = c & 0x1F;
      int m = arrayOfInt1[j] >>> k & 0x1;
      i ^= m;
      F.cswap(i, arrayOfInt3, arrayOfInt5);
      F.cswap(i, arrayOfInt4, arrayOfInt6);
      i = m;
      if (c < '\002') {
        for (j = 0; j < 2; j++)
          pointDouble(arrayOfInt3, arrayOfInt4); 
        F.inv(arrayOfInt4, arrayOfInt4);
        F.mul(arrayOfInt3, arrayOfInt4, arrayOfInt3);
        F.normalize(arrayOfInt3);
        F.encode(arrayOfInt3, paramArrayOfbyte3, paramInt3);
        return;
      } 
    } 
  }
  
  public static void scalarMultBase(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    Ed448.scalarMultBaseXY(Friend.INSTANCE, paramArrayOfbyte1, paramInt1, arrayOfInt1, arrayOfInt2);
    F.inv(arrayOfInt1, arrayOfInt1);
    F.mul(arrayOfInt1, arrayOfInt2, arrayOfInt1);
    F.sqr(arrayOfInt1, arrayOfInt1);
    F.normalize(arrayOfInt1);
    F.encode(arrayOfInt1, paramArrayOfbyte2, paramInt2);
  }
  
  private static class F extends X448Field {}
  
  public static class Friend {
    private static final Friend INSTANCE = new Friend();
  }
}
