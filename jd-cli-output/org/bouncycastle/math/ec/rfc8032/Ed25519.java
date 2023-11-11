package org.bouncycastle.math.ec.rfc8032;

import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.math.ec.rfc7748.X25519Field;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

public abstract class Ed25519 {
  private static final long M08L = 255L;
  
  private static final long M28L = 268435455L;
  
  private static final long M32L = 4294967295L;
  
  private static final int COORD_INTS = 8;
  
  private static final int POINT_BYTES = 32;
  
  private static final int SCALAR_INTS = 8;
  
  private static final int SCALAR_BYTES = 32;
  
  public static final int PREHASH_SIZE = 64;
  
  public static final int PUBLIC_KEY_SIZE = 32;
  
  public static final int SECRET_KEY_SIZE = 32;
  
  public static final int SIGNATURE_SIZE = 64;
  
  private static final byte[] DOM2_PREFIX = new byte[] { 
      83, 105, 103, 69, 100, 50, 53, 53, 49, 57, 
      32, 110, 111, 32, 69, 100, 50, 53, 53, 49, 
      57, 32, 99, 111, 108, 108, 105, 115, 105, 111, 
      110, 115 };
  
  private static final int[] P = new int[] { -19, -1, -1, -1, -1, -1, -1, Integer.MAX_VALUE };
  
  private static final int[] L = new int[] { 1559614445, 1477600026, -1560830762, 350157278, 0, 0, 0, 268435456 };
  
  private static final int L0 = -50998291;
  
  private static final int L1 = 19280294;
  
  private static final int L2 = 127719000;
  
  private static final int L3 = -6428113;
  
  private static final int L4 = 5343;
  
  private static final int[] B_x = new int[] { 52811034, 25909283, 8072341, 50637101, 13785486, 30858332, 20483199, 20966410, 43936626, 4379245 };
  
  private static final int[] B_y = new int[] { 40265304, 26843545, 6710886, 53687091, 13421772, 40265318, 26843545, 6710886, 53687091, 13421772 };
  
  private static final int[] C_d = new int[] { 56195235, 47411844, 25868126, 40503822, 57364, 58321048, 30416477, 31930572, 57760639, 10749657 };
  
  private static final int[] C_d2 = new int[] { 45281625, 27714825, 18181821, 13898781, 114729, 49533232, 60832955, 30306712, 48412415, 4722099 };
  
  private static final int[] C_d4 = new int[] { 23454386, 55429651, 2809210, 27797563, 229458, 31957600, 54557047, 27058993, 29715967, 9444199 };
  
  private static final int WNAF_WIDTH_BASE = 7;
  
  private static final int PRECOMP_BLOCKS = 8;
  
  private static final int PRECOMP_TEETH = 4;
  
  private static final int PRECOMP_SPACING = 8;
  
  private static final int PRECOMP_POINTS = 8;
  
  private static final int PRECOMP_MASK = 7;
  
  private static final Object precompLock = new Object();
  
  private static PointExt[] precompBaseTable = null;
  
  private static int[] precompBase = null;
  
  private static byte[] calculateS(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    int[] arrayOfInt1 = new int[16];
    decodeScalar(paramArrayOfbyte1, 0, arrayOfInt1);
    int[] arrayOfInt2 = new int[8];
    decodeScalar(paramArrayOfbyte2, 0, arrayOfInt2);
    int[] arrayOfInt3 = new int[8];
    decodeScalar(paramArrayOfbyte3, 0, arrayOfInt3);
    Nat256.mulAddTo(arrayOfInt2, arrayOfInt3, arrayOfInt1);
    byte[] arrayOfByte = new byte[64];
    for (byte b = 0; b < arrayOfInt1.length; b++)
      encode32(arrayOfInt1[b], arrayOfByte, b * 4); 
    return reduceScalar(arrayOfByte);
  }
  
  private static boolean checkContextVar(byte[] paramArrayOfbyte, byte paramByte) {
    return ((paramArrayOfbyte == null && paramByte == 0) || (paramArrayOfbyte != null && paramArrayOfbyte.length < 256));
  }
  
  private static int checkPoint(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    F.sqr(paramArrayOfint1, arrayOfInt2);
    F.sqr(paramArrayOfint2, arrayOfInt3);
    F.mul(arrayOfInt2, arrayOfInt3, arrayOfInt1);
    F.sub(arrayOfInt3, arrayOfInt2, arrayOfInt3);
    F.mul(arrayOfInt1, C_d, arrayOfInt1);
    F.addOne(arrayOfInt1);
    F.sub(arrayOfInt1, arrayOfInt3, arrayOfInt1);
    F.normalize(arrayOfInt1);
    return F.isZero(arrayOfInt1);
  }
  
  private static int checkPoint(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = F.create();
    F.sqr(paramArrayOfint1, arrayOfInt2);
    F.sqr(paramArrayOfint2, arrayOfInt3);
    F.sqr(paramArrayOfint3, arrayOfInt4);
    F.mul(arrayOfInt2, arrayOfInt3, arrayOfInt1);
    F.sub(arrayOfInt3, arrayOfInt2, arrayOfInt3);
    F.mul(arrayOfInt3, arrayOfInt4, arrayOfInt3);
    F.sqr(arrayOfInt4, arrayOfInt4);
    F.mul(arrayOfInt1, C_d, arrayOfInt1);
    F.add(arrayOfInt1, arrayOfInt4, arrayOfInt1);
    F.sub(arrayOfInt1, arrayOfInt3, arrayOfInt1);
    F.normalize(arrayOfInt1);
    return F.isZero(arrayOfInt1);
  }
  
  private static boolean checkPointVar(byte[] paramArrayOfbyte) {
    int[] arrayOfInt = new int[8];
    decode32(paramArrayOfbyte, 0, arrayOfInt, 0, 8);
    arrayOfInt[7] = arrayOfInt[7] & Integer.MAX_VALUE;
    return !Nat256.gte(arrayOfInt, P);
  }
  
  private static boolean checkScalarVar(byte[] paramArrayOfbyte, int[] paramArrayOfint) {
    decodeScalar(paramArrayOfbyte, 0, paramArrayOfint);
    return !Nat256.gte(paramArrayOfint, L);
  }
  
  private static byte[] copy(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = new byte[paramInt2];
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte, 0, paramInt2);
    return arrayOfByte;
  }
  
  private static Digest createDigest() {
    return new SHA512Digest();
  }
  
  public static Digest createPrehash() {
    return createDigest();
  }
  
  private static int decode24(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    return i;
  }
  
  private static int decode32(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 16;
    i |= paramArrayOfbyte[++paramInt] << 24;
    return i;
  }
  
  private static void decode32(byte[] paramArrayOfbyte, int paramInt1, int[] paramArrayOfint, int paramInt2, int paramInt3) {
    for (byte b = 0; b < paramInt3; b++)
      paramArrayOfint[paramInt2 + b] = decode32(paramArrayOfbyte, paramInt1 + b * 4); 
  }
  
  private static boolean decodePointVar(byte[] paramArrayOfbyte, int paramInt, boolean paramBoolean, PointAffine paramPointAffine) {
    byte[] arrayOfByte = copy(paramArrayOfbyte, paramInt, 32);
    if (!checkPointVar(arrayOfByte))
      return false; 
    int i = (arrayOfByte[31] & 0x80) >>> 7;
    arrayOfByte[31] = (byte)(arrayOfByte[31] & Byte.MAX_VALUE);
    F.decode(arrayOfByte, 0, paramPointAffine.y);
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    F.sqr(paramPointAffine.y, arrayOfInt1);
    F.mul(C_d, arrayOfInt1, arrayOfInt2);
    F.subOne(arrayOfInt1);
    F.addOne(arrayOfInt2);
    if (!F.sqrtRatioVar(arrayOfInt1, arrayOfInt2, paramPointAffine.x))
      return false; 
    F.normalize(paramPointAffine.x);
    if (i == 1 && F.isZeroVar(paramPointAffine.x))
      return false; 
    if ((paramBoolean ^ ((i != (paramPointAffine.x[0] & 0x1)) ? 1 : 0)) != 0)
      F.negate(paramPointAffine.x, paramPointAffine.x); 
    return true;
  }
  
  private static void decodeScalar(byte[] paramArrayOfbyte, int paramInt, int[] paramArrayOfint) {
    decode32(paramArrayOfbyte, paramInt, paramArrayOfint, 0, 8);
  }
  
  private static void dom2(Digest paramDigest, byte paramByte, byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte != null) {
      int i = DOM2_PREFIX.length;
      byte[] arrayOfByte = new byte[i + 2 + paramArrayOfbyte.length];
      System.arraycopy(DOM2_PREFIX, 0, arrayOfByte, 0, i);
      arrayOfByte[i] = paramByte;
      arrayOfByte[i + 1] = (byte)paramArrayOfbyte.length;
      System.arraycopy(paramArrayOfbyte, 0, arrayOfByte, i + 2, paramArrayOfbyte.length);
      paramDigest.update(arrayOfByte, 0, arrayOfByte.length);
    } 
  }
  
  private static void encode24(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    paramArrayOfbyte[paramInt2] = (byte)paramInt1;
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 8);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 16);
  }
  
  private static void encode32(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    paramArrayOfbyte[paramInt2] = (byte)paramInt1;
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 8);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 16);
    paramArrayOfbyte[++paramInt2] = (byte)(paramInt1 >>> 24);
  }
  
  private static void encode56(long paramLong, byte[] paramArrayOfbyte, int paramInt) {
    encode32((int)paramLong, paramArrayOfbyte, paramInt);
    encode24((int)(paramLong >>> 32L), paramArrayOfbyte, paramInt + 4);
  }
  
  private static int encodePoint(PointAccum paramPointAccum, byte[] paramArrayOfbyte, int paramInt) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    F.inv(paramPointAccum.z, arrayOfInt2);
    F.mul(paramPointAccum.x, arrayOfInt2, arrayOfInt1);
    F.mul(paramPointAccum.y, arrayOfInt2, arrayOfInt2);
    F.normalize(arrayOfInt1);
    F.normalize(arrayOfInt2);
    int i = checkPoint(arrayOfInt1, arrayOfInt2);
    F.encode(arrayOfInt2, paramArrayOfbyte, paramInt);
    paramArrayOfbyte[paramInt + 32 - 1] = (byte)(paramArrayOfbyte[paramInt + 32 - 1] | (arrayOfInt1[0] & 0x1) << 7);
    return i;
  }
  
  public static void generatePrivateKey(SecureRandom paramSecureRandom, byte[] paramArrayOfbyte) {
    paramSecureRandom.nextBytes(paramArrayOfbyte);
  }
  
  public static void generatePublicKey(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    Digest digest = createDigest();
    byte[] arrayOfByte1 = new byte[digest.getDigestSize()];
    digest.update(paramArrayOfbyte1, paramInt1, 32);
    digest.doFinal(arrayOfByte1, 0);
    byte[] arrayOfByte2 = new byte[32];
    pruneScalar(arrayOfByte1, 0, arrayOfByte2);
    scalarMultBaseEncoded(arrayOfByte2, paramArrayOfbyte2, paramInt2);
  }
  
  private static int getWindow4(int[] paramArrayOfint, int paramInt) {
    int i = paramInt >>> 3;
    int j = (paramInt & 0x7) << 2;
    return paramArrayOfint[i] >>> j & 0xF;
  }
  
  private static byte[] getWnafVar(int[] paramArrayOfint, int paramInt) {
    int[] arrayOfInt = new int[16];
    int i = arrayOfInt.length;
    int j = 0;
    int k = 8;
    while (--k >= 0) {
      int n = paramArrayOfint[k];
      arrayOfInt[--i] = n >>> 16 | j << 16;
      arrayOfInt[--i] = j = n;
    } 
    byte[] arrayOfByte = new byte[253];
    j = 32 - paramInt;
    k = 0;
    int m = 0;
    byte b = 0;
    while (b < arrayOfInt.length) {
      int n = arrayOfInt[b];
      while (k < 16) {
        int i1 = n >>> k;
        int i2 = i1 & 0x1;
        if (i2 == m) {
          k++;
          continue;
        } 
        int i3 = (i1 | 0x1) << j;
        m = i3 >>> 31;
        arrayOfByte[(b << 4) + k] = (byte)(i3 >> j);
        k += paramInt;
      } 
      b++;
      k -= 16;
    } 
    return arrayOfByte;
  }
  
  private static void implSign(Digest paramDigest, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, int paramInt1, byte[] paramArrayOfbyte4, byte paramByte, byte[] paramArrayOfbyte5, int paramInt2, int paramInt3, byte[] paramArrayOfbyte6, int paramInt4) {
    dom2(paramDigest, paramByte, paramArrayOfbyte4);
    paramDigest.update(paramArrayOfbyte1, 32, 32);
    paramDigest.update(paramArrayOfbyte5, paramInt2, paramInt3);
    paramDigest.doFinal(paramArrayOfbyte1, 0);
    byte[] arrayOfByte1 = reduceScalar(paramArrayOfbyte1);
    byte[] arrayOfByte2 = new byte[32];
    scalarMultBaseEncoded(arrayOfByte1, arrayOfByte2, 0);
    dom2(paramDigest, paramByte, paramArrayOfbyte4);
    paramDigest.update(arrayOfByte2, 0, 32);
    paramDigest.update(paramArrayOfbyte3, paramInt1, 32);
    paramDigest.update(paramArrayOfbyte5, paramInt2, paramInt3);
    paramDigest.doFinal(paramArrayOfbyte1, 0);
    byte[] arrayOfByte3 = reduceScalar(paramArrayOfbyte1);
    byte[] arrayOfByte4 = calculateS(arrayOfByte1, arrayOfByte3, paramArrayOfbyte2);
    System.arraycopy(arrayOfByte2, 0, paramArrayOfbyte6, paramInt4, 32);
    System.arraycopy(arrayOfByte4, 0, paramArrayOfbyte6, paramInt4 + 32, 32);
  }
  
  private static void implSign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, byte paramByte, byte[] paramArrayOfbyte3, int paramInt2, int paramInt3, byte[] paramArrayOfbyte4, int paramInt4) {
    if (!checkContextVar(paramArrayOfbyte2, paramByte))
      throw new IllegalArgumentException("ctx"); 
    Digest digest = createDigest();
    byte[] arrayOfByte1 = new byte[digest.getDigestSize()];
    digest.update(paramArrayOfbyte1, paramInt1, 32);
    digest.doFinal(arrayOfByte1, 0);
    byte[] arrayOfByte2 = new byte[32];
    pruneScalar(arrayOfByte1, 0, arrayOfByte2);
    byte[] arrayOfByte3 = new byte[32];
    scalarMultBaseEncoded(arrayOfByte2, arrayOfByte3, 0);
    implSign(digest, arrayOfByte1, arrayOfByte2, arrayOfByte3, 0, paramArrayOfbyte2, paramByte, paramArrayOfbyte3, paramInt2, paramInt3, paramArrayOfbyte4, paramInt4);
  }
  
  private static void implSign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte paramByte, byte[] paramArrayOfbyte4, int paramInt3, int paramInt4, byte[] paramArrayOfbyte5, int paramInt5) {
    if (!checkContextVar(paramArrayOfbyte3, paramByte))
      throw new IllegalArgumentException("ctx"); 
    Digest digest = createDigest();
    byte[] arrayOfByte1 = new byte[digest.getDigestSize()];
    digest.update(paramArrayOfbyte1, paramInt1, 32);
    digest.doFinal(arrayOfByte1, 0);
    byte[] arrayOfByte2 = new byte[32];
    pruneScalar(arrayOfByte1, 0, arrayOfByte2);
    implSign(digest, arrayOfByte1, arrayOfByte2, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, paramByte, paramArrayOfbyte4, paramInt3, paramInt4, paramArrayOfbyte5, paramInt5);
  }
  
  private static boolean implVerify(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte paramByte, byte[] paramArrayOfbyte4, int paramInt3, int paramInt4) {
    if (!checkContextVar(paramArrayOfbyte3, paramByte))
      throw new IllegalArgumentException("ctx"); 
    byte[] arrayOfByte1 = copy(paramArrayOfbyte1, paramInt1, 32);
    byte[] arrayOfByte2 = copy(paramArrayOfbyte1, paramInt1 + 32, 32);
    if (!checkPointVar(arrayOfByte1))
      return false; 
    int[] arrayOfInt1 = new int[8];
    if (!checkScalarVar(arrayOfByte2, arrayOfInt1))
      return false; 
    PointAffine pointAffine = new PointAffine();
    if (!decodePointVar(paramArrayOfbyte2, paramInt2, true, pointAffine))
      return false; 
    Digest digest = createDigest();
    byte[] arrayOfByte3 = new byte[digest.getDigestSize()];
    dom2(digest, paramByte, paramArrayOfbyte3);
    digest.update(arrayOfByte1, 0, 32);
    digest.update(paramArrayOfbyte2, paramInt2, 32);
    digest.update(paramArrayOfbyte4, paramInt3, paramInt4);
    digest.doFinal(arrayOfByte3, 0);
    byte[] arrayOfByte4 = reduceScalar(arrayOfByte3);
    int[] arrayOfInt2 = new int[8];
    decodeScalar(arrayOfByte4, 0, arrayOfInt2);
    PointAccum pointAccum = new PointAccum();
    scalarMultStrausVar(arrayOfInt1, arrayOfInt2, pointAffine, pointAccum);
    byte[] arrayOfByte5 = new byte[32];
    return (0 != encodePoint(pointAccum, arrayOfByte5, 0) && Arrays.areEqual(arrayOfByte5, arrayOfByte1));
  }
  
  private static boolean isNeutralElementVar(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    return (F.isZeroVar(paramArrayOfint1) && F.isOneVar(paramArrayOfint2));
  }
  
  private static boolean isNeutralElementVar(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    return (F.isZeroVar(paramArrayOfint1) && F.areEqualVar(paramArrayOfint2, paramArrayOfint3));
  }
  
  private static void pointAdd(PointExt paramPointExt, PointAccum paramPointAccum) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = F.create();
    int[] arrayOfInt5 = paramPointAccum.u;
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = F.create();
    int[] arrayOfInt8 = paramPointAccum.v;
    F.apm(paramPointAccum.y, paramPointAccum.x, arrayOfInt2, arrayOfInt1);
    F.apm(paramPointExt.y, paramPointExt.x, arrayOfInt4, arrayOfInt3);
    F.mul(arrayOfInt1, arrayOfInt3, arrayOfInt1);
    F.mul(arrayOfInt2, arrayOfInt4, arrayOfInt2);
    F.mul(paramPointAccum.u, paramPointAccum.v, arrayOfInt3);
    F.mul(arrayOfInt3, paramPointExt.t, arrayOfInt3);
    F.mul(arrayOfInt3, C_d2, arrayOfInt3);
    F.mul(paramPointAccum.z, paramPointExt.z, arrayOfInt4);
    F.add(arrayOfInt4, arrayOfInt4, arrayOfInt4);
    F.apm(arrayOfInt2, arrayOfInt1, arrayOfInt8, arrayOfInt5);
    F.apm(arrayOfInt4, arrayOfInt3, arrayOfInt7, arrayOfInt6);
    F.carry(arrayOfInt7);
    F.mul(arrayOfInt5, arrayOfInt6, paramPointAccum.x);
    F.mul(arrayOfInt7, arrayOfInt8, paramPointAccum.y);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointAccum.z);
  }
  
  private static void pointAdd(PointExt paramPointExt1, PointExt paramPointExt2) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = F.create();
    int[] arrayOfInt5 = F.create();
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = F.create();
    int[] arrayOfInt8 = F.create();
    F.apm(paramPointExt1.y, paramPointExt1.x, arrayOfInt2, arrayOfInt1);
    F.apm(paramPointExt2.y, paramPointExt2.x, arrayOfInt4, arrayOfInt3);
    F.mul(arrayOfInt1, arrayOfInt3, arrayOfInt1);
    F.mul(arrayOfInt2, arrayOfInt4, arrayOfInt2);
    F.mul(paramPointExt1.t, paramPointExt2.t, arrayOfInt3);
    F.mul(arrayOfInt3, C_d2, arrayOfInt3);
    F.mul(paramPointExt1.z, paramPointExt2.z, arrayOfInt4);
    F.add(arrayOfInt4, arrayOfInt4, arrayOfInt4);
    F.apm(arrayOfInt2, arrayOfInt1, arrayOfInt8, arrayOfInt5);
    F.apm(arrayOfInt4, arrayOfInt3, arrayOfInt7, arrayOfInt6);
    F.carry(arrayOfInt7);
    F.mul(arrayOfInt5, arrayOfInt6, paramPointExt2.x);
    F.mul(arrayOfInt7, arrayOfInt8, paramPointExt2.y);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointExt2.z);
    F.mul(arrayOfInt5, arrayOfInt8, paramPointExt2.t);
  }
  
  private static void pointAddVar(boolean paramBoolean, PointExt paramPointExt, PointAccum paramPointAccum) {
    int[] arrayOfInt9;
    int[] arrayOfInt10;
    int[] arrayOfInt11;
    int[] arrayOfInt12;
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = F.create();
    int[] arrayOfInt5 = paramPointAccum.u;
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = F.create();
    int[] arrayOfInt8 = paramPointAccum.v;
    if (paramBoolean) {
      arrayOfInt9 = arrayOfInt4;
      arrayOfInt10 = arrayOfInt3;
      arrayOfInt11 = arrayOfInt7;
      arrayOfInt12 = arrayOfInt6;
    } else {
      arrayOfInt9 = arrayOfInt3;
      arrayOfInt10 = arrayOfInt4;
      arrayOfInt11 = arrayOfInt6;
      arrayOfInt12 = arrayOfInt7;
    } 
    F.apm(paramPointAccum.y, paramPointAccum.x, arrayOfInt2, arrayOfInt1);
    F.apm(paramPointExt.y, paramPointExt.x, arrayOfInt10, arrayOfInt9);
    F.mul(arrayOfInt1, arrayOfInt3, arrayOfInt1);
    F.mul(arrayOfInt2, arrayOfInt4, arrayOfInt2);
    F.mul(paramPointAccum.u, paramPointAccum.v, arrayOfInt3);
    F.mul(arrayOfInt3, paramPointExt.t, arrayOfInt3);
    F.mul(arrayOfInt3, C_d2, arrayOfInt3);
    F.mul(paramPointAccum.z, paramPointExt.z, arrayOfInt4);
    F.add(arrayOfInt4, arrayOfInt4, arrayOfInt4);
    F.apm(arrayOfInt2, arrayOfInt1, arrayOfInt8, arrayOfInt5);
    F.apm(arrayOfInt4, arrayOfInt3, arrayOfInt12, arrayOfInt11);
    F.carry(arrayOfInt12);
    F.mul(arrayOfInt5, arrayOfInt6, paramPointAccum.x);
    F.mul(arrayOfInt7, arrayOfInt8, paramPointAccum.y);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointAccum.z);
  }
  
  private static void pointAddVar(boolean paramBoolean, PointExt paramPointExt1, PointExt paramPointExt2, PointExt paramPointExt3) {
    int[] arrayOfInt9;
    int[] arrayOfInt10;
    int[] arrayOfInt11;
    int[] arrayOfInt12;
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = F.create();
    int[] arrayOfInt5 = F.create();
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = F.create();
    int[] arrayOfInt8 = F.create();
    if (paramBoolean) {
      arrayOfInt9 = arrayOfInt4;
      arrayOfInt10 = arrayOfInt3;
      arrayOfInt11 = arrayOfInt7;
      arrayOfInt12 = arrayOfInt6;
    } else {
      arrayOfInt9 = arrayOfInt3;
      arrayOfInt10 = arrayOfInt4;
      arrayOfInt11 = arrayOfInt6;
      arrayOfInt12 = arrayOfInt7;
    } 
    F.apm(paramPointExt1.y, paramPointExt1.x, arrayOfInt2, arrayOfInt1);
    F.apm(paramPointExt2.y, paramPointExt2.x, arrayOfInt10, arrayOfInt9);
    F.mul(arrayOfInt1, arrayOfInt3, arrayOfInt1);
    F.mul(arrayOfInt2, arrayOfInt4, arrayOfInt2);
    F.mul(paramPointExt1.t, paramPointExt2.t, arrayOfInt3);
    F.mul(arrayOfInt3, C_d2, arrayOfInt3);
    F.mul(paramPointExt1.z, paramPointExt2.z, arrayOfInt4);
    F.add(arrayOfInt4, arrayOfInt4, arrayOfInt4);
    F.apm(arrayOfInt2, arrayOfInt1, arrayOfInt8, arrayOfInt5);
    F.apm(arrayOfInt4, arrayOfInt3, arrayOfInt12, arrayOfInt11);
    F.carry(arrayOfInt12);
    F.mul(arrayOfInt5, arrayOfInt6, paramPointExt3.x);
    F.mul(arrayOfInt7, arrayOfInt8, paramPointExt3.y);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointExt3.z);
    F.mul(arrayOfInt5, arrayOfInt8, paramPointExt3.t);
  }
  
  private static void pointAddPrecomp(PointPrecomp paramPointPrecomp, PointAccum paramPointAccum) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = paramPointAccum.u;
    int[] arrayOfInt5 = F.create();
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = paramPointAccum.v;
    F.apm(paramPointAccum.y, paramPointAccum.x, arrayOfInt2, arrayOfInt1);
    F.mul(arrayOfInt1, paramPointPrecomp.ymx_h, arrayOfInt1);
    F.mul(arrayOfInt2, paramPointPrecomp.ypx_h, arrayOfInt2);
    F.mul(paramPointAccum.u, paramPointAccum.v, arrayOfInt3);
    F.mul(arrayOfInt3, paramPointPrecomp.xyd, arrayOfInt3);
    F.apm(arrayOfInt2, arrayOfInt1, arrayOfInt7, arrayOfInt4);
    F.apm(paramPointAccum.z, arrayOfInt3, arrayOfInt6, arrayOfInt5);
    F.carry(arrayOfInt6);
    F.mul(arrayOfInt4, arrayOfInt5, paramPointAccum.x);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointAccum.y);
    F.mul(arrayOfInt5, arrayOfInt6, paramPointAccum.z);
  }
  
  private static PointExt pointCopy(PointAccum paramPointAccum) {
    PointExt pointExt = new PointExt();
    F.copy(paramPointAccum.x, 0, pointExt.x, 0);
    F.copy(paramPointAccum.y, 0, pointExt.y, 0);
    F.copy(paramPointAccum.z, 0, pointExt.z, 0);
    F.mul(paramPointAccum.u, paramPointAccum.v, pointExt.t);
    return pointExt;
  }
  
  private static PointExt pointCopy(PointAffine paramPointAffine) {
    PointExt pointExt = new PointExt();
    F.copy(paramPointAffine.x, 0, pointExt.x, 0);
    F.copy(paramPointAffine.y, 0, pointExt.y, 0);
    pointExtendXY(pointExt);
    return pointExt;
  }
  
  private static PointExt pointCopy(PointExt paramPointExt) {
    PointExt pointExt = new PointExt();
    pointCopy(paramPointExt, pointExt);
    return pointExt;
  }
  
  private static void pointCopy(PointAffine paramPointAffine, PointAccum paramPointAccum) {
    F.copy(paramPointAffine.x, 0, paramPointAccum.x, 0);
    F.copy(paramPointAffine.y, 0, paramPointAccum.y, 0);
    pointExtendXY(paramPointAccum);
  }
  
  private static void pointCopy(PointExt paramPointExt1, PointExt paramPointExt2) {
    F.copy(paramPointExt1.x, 0, paramPointExt2.x, 0);
    F.copy(paramPointExt1.y, 0, paramPointExt2.y, 0);
    F.copy(paramPointExt1.z, 0, paramPointExt2.z, 0);
    F.copy(paramPointExt1.t, 0, paramPointExt2.t, 0);
  }
  
  private static void pointDouble(PointAccum paramPointAccum) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = paramPointAccum.u;
    int[] arrayOfInt5 = F.create();
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = paramPointAccum.v;
    F.sqr(paramPointAccum.x, arrayOfInt1);
    F.sqr(paramPointAccum.y, arrayOfInt2);
    F.sqr(paramPointAccum.z, arrayOfInt3);
    F.add(arrayOfInt3, arrayOfInt3, arrayOfInt3);
    F.apm(arrayOfInt1, arrayOfInt2, arrayOfInt7, arrayOfInt6);
    F.add(paramPointAccum.x, paramPointAccum.y, arrayOfInt4);
    F.sqr(arrayOfInt4, arrayOfInt4);
    F.sub(arrayOfInt7, arrayOfInt4, arrayOfInt4);
    F.add(arrayOfInt3, arrayOfInt6, arrayOfInt5);
    F.carry(arrayOfInt5);
    F.mul(arrayOfInt4, arrayOfInt5, paramPointAccum.x);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointAccum.y);
    F.mul(arrayOfInt5, arrayOfInt6, paramPointAccum.z);
  }
  
  private static void pointExtendXY(PointAccum paramPointAccum) {
    F.one(paramPointAccum.z);
    F.copy(paramPointAccum.x, 0, paramPointAccum.u, 0);
    F.copy(paramPointAccum.y, 0, paramPointAccum.v, 0);
  }
  
  private static void pointExtendXY(PointExt paramPointExt) {
    F.one(paramPointExt.z);
    F.mul(paramPointExt.x, paramPointExt.y, paramPointExt.t);
  }
  
  private static void pointLookup(int paramInt1, int paramInt2, PointPrecomp paramPointPrecomp) {
    int i = paramInt1 * 8 * 3 * 10;
    for (byte b = 0; b < 8; b++) {
      int j = (b ^ paramInt2) - 1 >> 31;
      F.cmov(j, precompBase, i, paramPointPrecomp.ypx_h, 0);
      i += 10;
      F.cmov(j, precompBase, i, paramPointPrecomp.ymx_h, 0);
      i += 10;
      F.cmov(j, precompBase, i, paramPointPrecomp.xyd, 0);
      i += 10;
    } 
  }
  
  private static void pointLookup(int[] paramArrayOfint1, int paramInt, int[] paramArrayOfint2, PointExt paramPointExt) {
    int i = getWindow4(paramArrayOfint1, paramInt);
    int j = i >>> 3 ^ 0x1;
    int k = (i ^ -j) & 0x7;
    byte b = 0;
    boolean bool = false;
    while (b < 8) {
      int m = (b ^ k) - 1 >> 31;
      F.cmov(m, paramArrayOfint2, bool, paramPointExt.x, 0);
      bool += true;
      F.cmov(m, paramArrayOfint2, bool, paramPointExt.y, 0);
      bool += true;
      F.cmov(m, paramArrayOfint2, bool, paramPointExt.z, 0);
      bool += true;
      F.cmov(m, paramArrayOfint2, bool, paramPointExt.t, 0);
      bool += true;
      b++;
    } 
    F.cnegate(j, paramPointExt.x);
    F.cnegate(j, paramPointExt.t);
  }
  
  private static void pointLookup(int[] paramArrayOfint, int paramInt, PointExt paramPointExt) {
    int i = 40 * paramInt;
    F.copy(paramArrayOfint, i, paramPointExt.x, 0);
    i += 10;
    F.copy(paramArrayOfint, i, paramPointExt.y, 0);
    i += 10;
    F.copy(paramArrayOfint, i, paramPointExt.z, 0);
    i += 10;
    F.copy(paramArrayOfint, i, paramPointExt.t, 0);
  }
  
  private static int[] pointPrecompute(PointAffine paramPointAffine, int paramInt) {
    PointExt pointExt1 = pointCopy(paramPointAffine);
    PointExt pointExt2 = pointCopy(pointExt1);
    pointAdd(pointExt1, pointExt2);
    int[] arrayOfInt = F.createTable(paramInt * 4);
    boolean bool = false;
    byte b = 0;
    while (true) {
      F.copy(pointExt1.x, 0, arrayOfInt, bool);
      bool += true;
      F.copy(pointExt1.y, 0, arrayOfInt, bool);
      bool += true;
      F.copy(pointExt1.z, 0, arrayOfInt, bool);
      bool += true;
      F.copy(pointExt1.t, 0, arrayOfInt, bool);
      bool += true;
      if (++b == paramInt)
        return arrayOfInt; 
      pointAdd(pointExt2, pointExt1);
    } 
  }
  
  private static PointExt[] pointPrecomputeVar(PointExt paramPointExt, int paramInt) {
    PointExt pointExt = new PointExt();
    pointAddVar(false, paramPointExt, paramPointExt, pointExt);
    PointExt[] arrayOfPointExt = new PointExt[paramInt];
    arrayOfPointExt[0] = pointCopy(paramPointExt);
    for (byte b = 1; b < paramInt; b++)
      pointAddVar(false, arrayOfPointExt[b - 1], pointExt, arrayOfPointExt[b] = new PointExt()); 
    return arrayOfPointExt;
  }
  
  private static void pointSetNeutral(PointAccum paramPointAccum) {
    F.zero(paramPointAccum.x);
    F.one(paramPointAccum.y);
    F.one(paramPointAccum.z);
    F.zero(paramPointAccum.u);
    F.one(paramPointAccum.v);
  }
  
  private static void pointSetNeutral(PointExt paramPointExt) {
    F.zero(paramPointExt.x);
    F.one(paramPointExt.y);
    F.one(paramPointExt.z);
    F.zero(paramPointExt.t);
  }
  
  public static void precompute() {
    synchronized (precompLock) {
      if (precompBase != null)
        return; 
      PointExt pointExt = new PointExt();
      F.copy(B_x, 0, pointExt.x, 0);
      F.copy(B_y, 0, pointExt.y, 0);
      pointExtendXY(pointExt);
      precompBaseTable = pointPrecomputeVar(pointExt, 32);
      PointAccum pointAccum = new PointAccum();
      F.copy(B_x, 0, pointAccum.x, 0);
      F.copy(B_y, 0, pointAccum.y, 0);
      pointExtendXY(pointAccum);
      precompBase = F.createTable(192);
      boolean bool = false;
      for (byte b = 0; b < 8; b++) {
        PointExt[] arrayOfPointExt1 = new PointExt[4];
        PointExt pointExt1 = new PointExt();
        pointSetNeutral(pointExt1);
        for (byte b1 = 0; b1 < 4; b1++) {
          PointExt pointExt2 = pointCopy(pointAccum);
          pointAddVar(true, pointExt1, pointExt2, pointExt1);
          pointDouble(pointAccum);
          arrayOfPointExt1[b1] = pointCopy(pointAccum);
          if (b + b1 != 10)
            for (byte b6 = 1; b6 < 8; b6++)
              pointDouble(pointAccum);  
        } 
        PointExt[] arrayOfPointExt2 = new PointExt[8];
        byte b2 = 0;
        arrayOfPointExt2[b2++] = pointExt1;
        for (byte b3 = 0; b3 < 3; b3++) {
          int i = 1 << b3;
          byte b6 = 0;
          while (b6 < i) {
            pointAddVar(false, arrayOfPointExt2[b2 - i], arrayOfPointExt1[b3], arrayOfPointExt2[b2] = new PointExt());
            b6++;
            b2++;
          } 
        } 
        int[] arrayOfInt1 = F.createTable(8);
        int[] arrayOfInt2 = F.create();
        F.copy((arrayOfPointExt2[0]).z, 0, arrayOfInt2, 0);
        F.copy(arrayOfInt2, 0, arrayOfInt1, 0);
        byte b5 = 0;
        while (++b5 < 8) {
          F.mul(arrayOfInt2, (arrayOfPointExt2[b5]).z, arrayOfInt2);
          F.copy(arrayOfInt2, 0, arrayOfInt1, b5 * 10);
        } 
        F.add(arrayOfInt2, arrayOfInt2, arrayOfInt2);
        F.invVar(arrayOfInt2, arrayOfInt2);
        b5--;
        int[] arrayOfInt3 = F.create();
        while (b5 > 0) {
          byte b6 = b5--;
          F.copy(arrayOfInt1, b5 * 10, arrayOfInt3, 0);
          F.mul(arrayOfInt3, arrayOfInt2, arrayOfInt3);
          F.copy(arrayOfInt3, 0, arrayOfInt1, b6 * 10);
          F.mul(arrayOfInt2, (arrayOfPointExt2[b6]).z, arrayOfInt2);
        } 
        F.copy(arrayOfInt2, 0, arrayOfInt1, 0);
        for (byte b4 = 0; b4 < 8; b4++) {
          PointExt pointExt2 = arrayOfPointExt2[b4];
          arrayOfInt3 = F.create();
          int[] arrayOfInt = F.create();
          F.copy(arrayOfInt1, b4 * 10, arrayOfInt, 0);
          F.mul(pointExt2.x, arrayOfInt, arrayOfInt3);
          F.mul(pointExt2.y, arrayOfInt, arrayOfInt);
          PointPrecomp pointPrecomp = new PointPrecomp();
          F.apm(arrayOfInt, arrayOfInt3, pointPrecomp.ypx_h, pointPrecomp.ymx_h);
          F.mul(arrayOfInt3, arrayOfInt, pointPrecomp.xyd);
          F.mul(pointPrecomp.xyd, C_d4, pointPrecomp.xyd);
          F.normalize(pointPrecomp.ypx_h);
          F.normalize(pointPrecomp.ymx_h);
          F.copy(pointPrecomp.ypx_h, 0, precompBase, bool);
          bool += true;
          F.copy(pointPrecomp.ymx_h, 0, precompBase, bool);
          bool += true;
          F.copy(pointPrecomp.xyd, 0, precompBase, bool);
          bool += true;
        } 
      } 
    } 
  }
  
  private static void pruneScalar(byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2) {
    System.arraycopy(paramArrayOfbyte1, paramInt, paramArrayOfbyte2, 0, 32);
    paramArrayOfbyte2[0] = (byte)(paramArrayOfbyte2[0] & 0xF8);
    paramArrayOfbyte2[31] = (byte)(paramArrayOfbyte2[31] & Byte.MAX_VALUE);
    paramArrayOfbyte2[31] = (byte)(paramArrayOfbyte2[31] | 0x40);
  }
  
  private static byte[] reduceScalar(byte[] paramArrayOfbyte) {
    long l1 = decode32(paramArrayOfbyte, 0) & 0xFFFFFFFFL;
    long l2 = (decode24(paramArrayOfbyte, 4) << 4) & 0xFFFFFFFFL;
    long l3 = decode32(paramArrayOfbyte, 7) & 0xFFFFFFFFL;
    long l4 = (decode24(paramArrayOfbyte, 11) << 4) & 0xFFFFFFFFL;
    long l5 = decode32(paramArrayOfbyte, 14) & 0xFFFFFFFFL;
    long l6 = (decode24(paramArrayOfbyte, 18) << 4) & 0xFFFFFFFFL;
    long l7 = decode32(paramArrayOfbyte, 21) & 0xFFFFFFFFL;
    long l8 = (decode24(paramArrayOfbyte, 25) << 4) & 0xFFFFFFFFL;
    long l9 = decode32(paramArrayOfbyte, 28) & 0xFFFFFFFFL;
    long l10 = (decode24(paramArrayOfbyte, 32) << 4) & 0xFFFFFFFFL;
    long l11 = decode32(paramArrayOfbyte, 35) & 0xFFFFFFFFL;
    long l12 = (decode24(paramArrayOfbyte, 39) << 4) & 0xFFFFFFFFL;
    long l13 = decode32(paramArrayOfbyte, 42) & 0xFFFFFFFFL;
    long l14 = (decode24(paramArrayOfbyte, 46) << 4) & 0xFFFFFFFFL;
    long l15 = decode32(paramArrayOfbyte, 49) & 0xFFFFFFFFL;
    long l16 = (decode24(paramArrayOfbyte, 53) << 4) & 0xFFFFFFFFL;
    long l17 = decode32(paramArrayOfbyte, 56) & 0xFFFFFFFFL;
    long l18 = (decode24(paramArrayOfbyte, 60) << 4) & 0xFFFFFFFFL;
    long l19 = paramArrayOfbyte[63] & 0xFFL;
    l10 -= l19 * -50998291L;
    l11 -= l19 * 19280294L;
    l12 -= l19 * 127719000L;
    l13 -= l19 * -6428113L;
    l14 -= l19 * 5343L;
    l18 += l17 >> 28L;
    l17 &= 0xFFFFFFFL;
    l9 -= l18 * -50998291L;
    l10 -= l18 * 19280294L;
    l11 -= l18 * 127719000L;
    l12 -= l18 * -6428113L;
    l13 -= l18 * 5343L;
    l8 -= l17 * -50998291L;
    l9 -= l17 * 19280294L;
    l10 -= l17 * 127719000L;
    l11 -= l17 * -6428113L;
    l12 -= l17 * 5343L;
    l16 += l15 >> 28L;
    l15 &= 0xFFFFFFFL;
    l7 -= l16 * -50998291L;
    l8 -= l16 * 19280294L;
    l9 -= l16 * 127719000L;
    l10 -= l16 * -6428113L;
    l11 -= l16 * 5343L;
    l6 -= l15 * -50998291L;
    l7 -= l15 * 19280294L;
    l8 -= l15 * 127719000L;
    l9 -= l15 * -6428113L;
    l10 -= l15 * 5343L;
    l14 += l13 >> 28L;
    l13 &= 0xFFFFFFFL;
    l5 -= l14 * -50998291L;
    l6 -= l14 * 19280294L;
    l7 -= l14 * 127719000L;
    l8 -= l14 * -6428113L;
    l9 -= l14 * 5343L;
    l13 += l12 >> 28L;
    l12 &= 0xFFFFFFFL;
    l4 -= l13 * -50998291L;
    l5 -= l13 * 19280294L;
    l6 -= l13 * 127719000L;
    l7 -= l13 * -6428113L;
    l8 -= l13 * 5343L;
    l12 += l11 >> 28L;
    l11 &= 0xFFFFFFFL;
    l3 -= l12 * -50998291L;
    l4 -= l12 * 19280294L;
    l5 -= l12 * 127719000L;
    l6 -= l12 * -6428113L;
    l7 -= l12 * 5343L;
    l11 += l10 >> 28L;
    l10 &= 0xFFFFFFFL;
    l2 -= l11 * -50998291L;
    l3 -= l11 * 19280294L;
    l4 -= l11 * 127719000L;
    l5 -= l11 * -6428113L;
    l6 -= l11 * 5343L;
    l9 += l8 >> 28L;
    l8 &= 0xFFFFFFFL;
    l10 += l9 >> 28L;
    l9 &= 0xFFFFFFFL;
    long l20 = l9 >>> 27L;
    l10 += l20;
    l1 -= l10 * -50998291L;
    l2 -= l10 * 19280294L;
    l3 -= l10 * 127719000L;
    l4 -= l10 * -6428113L;
    l5 -= l10 * 5343L;
    l2 += l1 >> 28L;
    l1 &= 0xFFFFFFFL;
    l3 += l2 >> 28L;
    l2 &= 0xFFFFFFFL;
    l4 += l3 >> 28L;
    l3 &= 0xFFFFFFFL;
    l5 += l4 >> 28L;
    l4 &= 0xFFFFFFFL;
    l6 += l5 >> 28L;
    l5 &= 0xFFFFFFFL;
    l7 += l6 >> 28L;
    l6 &= 0xFFFFFFFL;
    l8 += l7 >> 28L;
    l7 &= 0xFFFFFFFL;
    l9 += l8 >> 28L;
    l8 &= 0xFFFFFFFL;
    l10 = l9 >> 28L;
    l9 &= 0xFFFFFFFL;
    l10 -= l20;
    l1 += l10 & 0xFFFFFFFFFCF5D3EDL;
    l2 += l10 & 0x12631A6L;
    l3 += l10 & 0x79CD658L;
    l4 += l10 & 0xFFFFFFFFFF9DEA2FL;
    l5 += l10 & 0x14DFL;
    l2 += l1 >> 28L;
    l1 &= 0xFFFFFFFL;
    l3 += l2 >> 28L;
    l2 &= 0xFFFFFFFL;
    l4 += l3 >> 28L;
    l3 &= 0xFFFFFFFL;
    l5 += l4 >> 28L;
    l4 &= 0xFFFFFFFL;
    l6 += l5 >> 28L;
    l5 &= 0xFFFFFFFL;
    l7 += l6 >> 28L;
    l6 &= 0xFFFFFFFL;
    l8 += l7 >> 28L;
    l7 &= 0xFFFFFFFL;
    l9 += l8 >> 28L;
    l8 &= 0xFFFFFFFL;
    byte[] arrayOfByte = new byte[32];
    encode56(l1 | l2 << 28L, arrayOfByte, 0);
    encode56(l3 | l4 << 28L, arrayOfByte, 7);
    encode56(l5 | l6 << 28L, arrayOfByte, 14);
    encode56(l7 | l8 << 28L, arrayOfByte, 21);
    encode32((int)l9, arrayOfByte, 28);
    return arrayOfByte;
  }
  
  private static void scalarMult(byte[] paramArrayOfbyte, PointAffine paramPointAffine, PointAccum paramPointAccum) {
    int[] arrayOfInt1 = new int[8];
    decodeScalar(paramArrayOfbyte, 0, arrayOfInt1);
    Nat.shiftDownBits(8, arrayOfInt1, 3, 1);
    Nat.cadd(8, (arrayOfInt1[0] ^ 0xFFFFFFFF) & 0x1, arrayOfInt1, L, arrayOfInt1);
    Nat.shiftDownBit(8, arrayOfInt1, 0);
    int[] arrayOfInt2 = pointPrecompute(paramPointAffine, 8);
    PointExt pointExt = new PointExt();
    pointCopy(paramPointAffine, paramPointAccum);
    pointLookup(arrayOfInt2, 7, pointExt);
    pointAdd(pointExt, paramPointAccum);
    byte b = 62;
    while (true) {
      pointLookup(arrayOfInt1, b, arrayOfInt2, pointExt);
      pointAdd(pointExt, paramPointAccum);
      pointDouble(paramPointAccum);
      pointDouble(paramPointAccum);
      pointDouble(paramPointAccum);
      if (--b < 0)
        break; 
      pointDouble(paramPointAccum);
    } 
  }
  
  private static void scalarMultBase(byte[] paramArrayOfbyte, PointAccum paramPointAccum) {
    precompute();
    int[] arrayOfInt = new int[8];
    decodeScalar(paramArrayOfbyte, 0, arrayOfInt);
    Nat.cadd(8, (arrayOfInt[0] ^ 0xFFFFFFFF) & 0x1, arrayOfInt, L, arrayOfInt);
    Nat.shiftDownBit(8, arrayOfInt, 1);
    for (byte b1 = 0; b1 < 8; b1++)
      arrayOfInt[b1] = Interleave.shuffle2(arrayOfInt[b1]); 
    PointPrecomp pointPrecomp = new PointPrecomp();
    pointSetNeutral(paramPointAccum);
    byte b2 = 28;
    while (true) {
      for (byte b = 0; b < 8; b++) {
        int i = arrayOfInt[b] >>> b2;
        int j = i >>> 3 & 0x1;
        int k = (i ^ -j) & 0x7;
        pointLookup(b, k, pointPrecomp);
        F.cswap(j, pointPrecomp.ypx_h, pointPrecomp.ymx_h);
        F.cnegate(j, pointPrecomp.xyd);
        pointAddPrecomp(pointPrecomp, paramPointAccum);
      } 
      b2 -= 4;
      if (b2 < 0)
        break; 
      pointDouble(paramPointAccum);
    } 
  }
  
  private static void scalarMultBaseEncoded(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    PointAccum pointAccum = new PointAccum();
    scalarMultBase(paramArrayOfbyte1, pointAccum);
    if (0 == encodePoint(pointAccum, paramArrayOfbyte2, paramInt))
      throw new IllegalStateException(); 
  }
  
  public static void scalarMultBaseYZ(X25519.Friend paramFriend, byte[] paramArrayOfbyte, int paramInt, int[] paramArrayOfint1, int[] paramArrayOfint2) {
    if (null == paramFriend)
      throw new NullPointerException("This method is only for use by X25519"); 
    byte[] arrayOfByte = new byte[32];
    pruneScalar(paramArrayOfbyte, paramInt, arrayOfByte);
    PointAccum pointAccum = new PointAccum();
    scalarMultBase(arrayOfByte, pointAccum);
    if (0 == checkPoint(pointAccum.x, pointAccum.y, pointAccum.z))
      throw new IllegalStateException(); 
    F.copy(pointAccum.y, 0, paramArrayOfint1, 0);
    F.copy(pointAccum.z, 0, paramArrayOfint2, 0);
  }
  
  private static void scalarMultOrderVar(PointAffine paramPointAffine, PointAccum paramPointAccum) {
    byte[] arrayOfByte = getWnafVar(L, 5);
    PointExt[] arrayOfPointExt = pointPrecomputeVar(pointCopy(paramPointAffine), 8);
    pointSetNeutral(paramPointAccum);
    char c = 'ü';
    while (true) {
      byte b = arrayOfByte[c];
      if (b != 0) {
        int i = b >> 31;
        int j = (b ^ i) >>> 1;
        pointAddVar((i != 0), arrayOfPointExt[j], paramPointAccum);
      } 
      if (--c < '\000')
        break; 
      pointDouble(paramPointAccum);
    } 
  }
  
  private static void scalarMultStrausVar(int[] paramArrayOfint1, int[] paramArrayOfint2, PointAffine paramPointAffine, PointAccum paramPointAccum) {
    precompute();
    byte[] arrayOfByte1 = getWnafVar(paramArrayOfint1, 7);
    byte[] arrayOfByte2 = getWnafVar(paramArrayOfint2, 5);
    PointExt[] arrayOfPointExt = pointPrecomputeVar(pointCopy(paramPointAffine), 8);
    pointSetNeutral(paramPointAccum);
    char c = 'ü';
    while (true) {
      byte b1 = arrayOfByte1[c];
      if (b1 != 0) {
        int i = b1 >> 31;
        int j = (b1 ^ i) >>> 1;
        pointAddVar((i != 0), precompBaseTable[j], paramPointAccum);
      } 
      byte b2 = arrayOfByte2[c];
      if (b2 != 0) {
        int i = b2 >> 31;
        int j = (b2 ^ i) >>> 1;
        pointAddVar((i != 0), arrayOfPointExt[j], paramPointAccum);
      } 
      if (--c < '\000')
        break; 
      pointDouble(paramPointAccum);
    } 
  }
  
  public static void sign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, int paramInt3, byte[] paramArrayOfbyte3, int paramInt4) {
    byte[] arrayOfByte = null;
    boolean bool = false;
    implSign(paramArrayOfbyte1, paramInt1, arrayOfByte, bool, paramArrayOfbyte2, paramInt2, paramInt3, paramArrayOfbyte3, paramInt4);
  }
  
  public static void sign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, int paramInt3, int paramInt4, byte[] paramArrayOfbyte4, int paramInt5) {
    byte[] arrayOfByte = null;
    boolean bool = false;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, arrayOfByte, bool, paramArrayOfbyte3, paramInt3, paramInt4, paramArrayOfbyte4, paramInt5);
  }
  
  public static void sign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, int paramInt2, int paramInt3, byte[] paramArrayOfbyte4, int paramInt4) {
    boolean bool = false;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, bool, paramArrayOfbyte3, paramInt2, paramInt3, paramArrayOfbyte4, paramInt4);
  }
  
  public static void sign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, int paramInt3, int paramInt4, byte[] paramArrayOfbyte5, int paramInt5) {
    boolean bool = false;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, paramArrayOfbyte4, paramInt3, paramInt4, paramArrayOfbyte5, paramInt5);
  }
  
  public static void signPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, int paramInt2, byte[] paramArrayOfbyte4, int paramInt3) {
    boolean bool = true;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, bool, paramArrayOfbyte3, paramInt2, 64, paramArrayOfbyte4, paramInt3);
  }
  
  public static void signPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, int paramInt3, byte[] paramArrayOfbyte5, int paramInt4) {
    boolean bool = true;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, paramArrayOfbyte4, paramInt3, 64, paramArrayOfbyte5, paramInt4);
  }
  
  public static void signPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, Digest paramDigest, byte[] paramArrayOfbyte3, int paramInt2) {
    byte[] arrayOfByte = new byte[64];
    if (64 != paramDigest.doFinal(arrayOfByte, 0))
      throw new IllegalArgumentException("ph"); 
    boolean bool = true;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, bool, arrayOfByte, 0, arrayOfByte.length, paramArrayOfbyte3, paramInt2);
  }
  
  public static void signPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, Digest paramDigest, byte[] paramArrayOfbyte4, int paramInt3) {
    byte[] arrayOfByte = new byte[64];
    if (64 != paramDigest.doFinal(arrayOfByte, 0))
      throw new IllegalArgumentException("ph"); 
    boolean bool = true;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, arrayOfByte, 0, arrayOfByte.length, paramArrayOfbyte4, paramInt3);
  }
  
  public static boolean validatePublicKeyFull(byte[] paramArrayOfbyte, int paramInt) {
    PointAffine pointAffine = new PointAffine();
    if (!decodePointVar(paramArrayOfbyte, paramInt, false, pointAffine))
      return false; 
    F.normalize(pointAffine.x);
    F.normalize(pointAffine.y);
    if (isNeutralElementVar(pointAffine.x, pointAffine.y))
      return false; 
    PointAccum pointAccum = new PointAccum();
    scalarMultOrderVar(pointAffine, pointAccum);
    F.normalize(pointAccum.x);
    F.normalize(pointAccum.y);
    F.normalize(pointAccum.z);
    return isNeutralElementVar(pointAccum.x, pointAccum.y, pointAccum.z);
  }
  
  public static boolean validatePublicKeyPartial(byte[] paramArrayOfbyte, int paramInt) {
    PointAffine pointAffine = new PointAffine();
    return decodePointVar(paramArrayOfbyte, paramInt, false, pointAffine);
  }
  
  public static boolean verify(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, int paramInt3, int paramInt4) {
    byte[] arrayOfByte = null;
    boolean bool = false;
    return implVerify(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, arrayOfByte, bool, paramArrayOfbyte3, paramInt3, paramInt4);
  }
  
  public static boolean verify(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, int paramInt3, int paramInt4) {
    boolean bool = false;
    return implVerify(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, paramArrayOfbyte4, paramInt3, paramInt4);
  }
  
  public static boolean verifyPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, int paramInt3) {
    boolean bool = true;
    return implVerify(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, paramArrayOfbyte4, paramInt3, 64);
  }
  
  public static boolean verifyPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, Digest paramDigest) {
    byte[] arrayOfByte = new byte[64];
    if (64 != paramDigest.doFinal(arrayOfByte, 0))
      throw new IllegalArgumentException("ph"); 
    boolean bool = true;
    return implVerify(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, arrayOfByte, 0, arrayOfByte.length);
  }
  
  public static final class Algorithm {
    public static final int Ed25519 = 0;
    
    public static final int Ed25519ctx = 1;
    
    public static final int Ed25519ph = 2;
  }
  
  private static class F extends X25519Field {}
  
  private static class PointAccum {
    int[] x = Ed25519.F.create();
    
    int[] y = Ed25519.F.create();
    
    int[] z = Ed25519.F.create();
    
    int[] u = Ed25519.F.create();
    
    int[] v = Ed25519.F.create();
    
    private PointAccum() {}
  }
  
  private static class PointAffine {
    int[] x = Ed25519.F.create();
    
    int[] y = Ed25519.F.create();
    
    private PointAffine() {}
  }
  
  private static class PointExt {
    int[] x = Ed25519.F.create();
    
    int[] y = Ed25519.F.create();
    
    int[] z = Ed25519.F.create();
    
    int[] t = Ed25519.F.create();
    
    private PointExt() {}
  }
  
  private static class PointPrecomp {
    int[] ypx_h = Ed25519.F.create();
    
    int[] ymx_h = Ed25519.F.create();
    
    int[] xyd = Ed25519.F.create();
    
    private PointPrecomp() {}
  }
}
