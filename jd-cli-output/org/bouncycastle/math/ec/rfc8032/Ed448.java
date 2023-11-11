package org.bouncycastle.math.ec.rfc8032;

import java.security.SecureRandom;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.math.ec.rfc7748.X448Field;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;

public abstract class Ed448 {
  private static final long M26L = 67108863L;
  
  private static final long M28L = 268435455L;
  
  private static final long M32L = 4294967295L;
  
  private static final int COORD_INTS = 14;
  
  private static final int POINT_BYTES = 57;
  
  private static final int SCALAR_INTS = 14;
  
  private static final int SCALAR_BYTES = 57;
  
  public static final int PREHASH_SIZE = 64;
  
  public static final int PUBLIC_KEY_SIZE = 57;
  
  public static final int SECRET_KEY_SIZE = 57;
  
  public static final int SIGNATURE_SIZE = 114;
  
  private static final byte[] DOM4_PREFIX = new byte[] { 83, 105, 103, 69, 100, 52, 52, 56 };
  
  private static final int[] P = new int[] { 
      -1, -1, -1, -1, -1, -1, -1, -2, -1, -1, 
      -1, -1, -1, -1 };
  
  private static final int[] L = new int[] { 
      -1420278541, 595116690, -1916432555, 560775794, -1361693040, -1001465015, 2093622249, -1, -1, -1, 
      -1, -1, -1, 1073741823 };
  
  private static final int L_0 = 78101261;
  
  private static final int L_1 = 141809365;
  
  private static final int L_2 = 175155932;
  
  private static final int L_3 = 64542499;
  
  private static final int L_4 = 158326419;
  
  private static final int L_5 = 191173276;
  
  private static final int L_6 = 104575268;
  
  private static final int L_7 = 137584065;
  
  private static final int L4_0 = 43969588;
  
  private static final int L4_1 = 30366549;
  
  private static final int L4_2 = 163752818;
  
  private static final int L4_3 = 258169998;
  
  private static final int L4_4 = 96434764;
  
  private static final int L4_5 = 227822194;
  
  private static final int L4_6 = 149865618;
  
  private static final int L4_7 = 550336261;
  
  private static final int[] B_x = new int[] { 
      118276190, 40534716, 9670182, 135141552, 85017403, 259173222, 68333082, 171784774, 174973732, 15824510, 
      73756743, 57518561, 94773951, 248652241, 107736333, 82941708 };
  
  private static final int[] B_y = new int[] { 
      36764180, 8885695, 130592152, 20104429, 163904957, 30304195, 121295871, 5901357, 125344798, 171541512, 
      175338348, 209069246, 3626697, 38307682, 24032956, 110359655 };
  
  private static final int C_d = -39081;
  
  private static final int WNAF_WIDTH_BASE = 7;
  
  private static final int PRECOMP_BLOCKS = 5;
  
  private static final int PRECOMP_TEETH = 5;
  
  private static final int PRECOMP_SPACING = 18;
  
  private static final int PRECOMP_POINTS = 16;
  
  private static final int PRECOMP_MASK = 15;
  
  private static final Object precompLock = new Object();
  
  private static PointExt[] precompBaseTable = null;
  
  private static int[] precompBase = null;
  
  private static byte[] calculateS(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    int[] arrayOfInt1 = new int[28];
    decodeScalar(paramArrayOfbyte1, 0, arrayOfInt1);
    int[] arrayOfInt2 = new int[14];
    decodeScalar(paramArrayOfbyte2, 0, arrayOfInt2);
    int[] arrayOfInt3 = new int[14];
    decodeScalar(paramArrayOfbyte3, 0, arrayOfInt3);
    Nat.mulAddTo(14, arrayOfInt2, arrayOfInt3, arrayOfInt1);
    byte[] arrayOfByte = new byte[114];
    for (byte b = 0; b < arrayOfInt1.length; b++)
      encode32(arrayOfInt1[b], arrayOfByte, b * 4); 
    return reduceScalar(arrayOfByte);
  }
  
  private static boolean checkContextVar(byte[] paramArrayOfbyte) {
    return (paramArrayOfbyte != null && paramArrayOfbyte.length < 256);
  }
  
  private static int checkPoint(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    F.sqr(paramArrayOfint1, arrayOfInt2);
    F.sqr(paramArrayOfint2, arrayOfInt3);
    F.mul(arrayOfInt2, arrayOfInt3, arrayOfInt1);
    F.add(arrayOfInt2, arrayOfInt3, arrayOfInt2);
    F.mul(arrayOfInt1, 39081, arrayOfInt1);
    F.subOne(arrayOfInt1);
    F.add(arrayOfInt1, arrayOfInt2, arrayOfInt1);
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
    F.add(arrayOfInt2, arrayOfInt3, arrayOfInt2);
    F.mul(arrayOfInt2, arrayOfInt4, arrayOfInt2);
    F.sqr(arrayOfInt4, arrayOfInt4);
    F.mul(arrayOfInt1, 39081, arrayOfInt1);
    F.sub(arrayOfInt1, arrayOfInt4, arrayOfInt1);
    F.add(arrayOfInt1, arrayOfInt2, arrayOfInt1);
    F.normalize(arrayOfInt1);
    return F.isZero(arrayOfInt1);
  }
  
  private static boolean checkPointVar(byte[] paramArrayOfbyte) {
    if ((paramArrayOfbyte[56] & Byte.MAX_VALUE) != 0)
      return false; 
    int[] arrayOfInt = new int[14];
    decode32(paramArrayOfbyte, 0, arrayOfInt, 0, 14);
    return !Nat.gte(14, arrayOfInt, P);
  }
  
  private static boolean checkScalarVar(byte[] paramArrayOfbyte, int[] paramArrayOfint) {
    if (paramArrayOfbyte[56] != 0)
      return false; 
    decodeScalar(paramArrayOfbyte, 0, paramArrayOfint);
    return !Nat.gte(14, paramArrayOfint, L);
  }
  
  private static byte[] copy(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte = new byte[paramInt2];
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte, 0, paramInt2);
    return arrayOfByte;
  }
  
  public static Xof createPrehash() {
    return createXof();
  }
  
  private static Xof createXof() {
    return new SHAKEDigest(256);
  }
  
  private static int decode16(byte[] paramArrayOfbyte, int paramInt) {
    int i = paramArrayOfbyte[paramInt] & 0xFF;
    i |= (paramArrayOfbyte[++paramInt] & 0xFF) << 8;
    return i;
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
  
  private static boolean decodePointVar(byte[] paramArrayOfbyte, int paramInt, boolean paramBoolean, PointExt paramPointExt) {
    byte[] arrayOfByte = copy(paramArrayOfbyte, paramInt, 57);
    if (!checkPointVar(arrayOfByte))
      return false; 
    int i = (arrayOfByte[56] & 0x80) >>> 7;
    arrayOfByte[56] = (byte)(arrayOfByte[56] & Byte.MAX_VALUE);
    F.decode(arrayOfByte, 0, paramPointExt.y);
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    F.sqr(paramPointExt.y, arrayOfInt1);
    F.mul(arrayOfInt1, 39081, arrayOfInt2);
    F.negate(arrayOfInt1, arrayOfInt1);
    F.addOne(arrayOfInt1);
    F.addOne(arrayOfInt2);
    if (!F.sqrtRatioVar(arrayOfInt1, arrayOfInt2, paramPointExt.x))
      return false; 
    F.normalize(paramPointExt.x);
    if (i == 1 && F.isZeroVar(paramPointExt.x))
      return false; 
    if ((paramBoolean ^ ((i != (paramPointExt.x[0] & 0x1)) ? 1 : 0)) != 0)
      F.negate(paramPointExt.x, paramPointExt.x); 
    pointExtendXY(paramPointExt);
    return true;
  }
  
  private static void decodeScalar(byte[] paramArrayOfbyte, int paramInt, int[] paramArrayOfint) {
    decode32(paramArrayOfbyte, paramInt, paramArrayOfint, 0, 14);
  }
  
  private static void dom4(Xof paramXof, byte paramByte, byte[] paramArrayOfbyte) {
    int i = DOM4_PREFIX.length;
    byte[] arrayOfByte = new byte[i + 2 + paramArrayOfbyte.length];
    System.arraycopy(DOM4_PREFIX, 0, arrayOfByte, 0, i);
    arrayOfByte[i] = paramByte;
    arrayOfByte[i + 1] = (byte)paramArrayOfbyte.length;
    System.arraycopy(paramArrayOfbyte, 0, arrayOfByte, i + 2, paramArrayOfbyte.length);
    paramXof.update(arrayOfByte, 0, arrayOfByte.length);
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
  
  private static int encodePoint(PointExt paramPointExt, byte[] paramArrayOfbyte, int paramInt) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    F.inv(paramPointExt.z, arrayOfInt2);
    F.mul(paramPointExt.x, arrayOfInt2, arrayOfInt1);
    F.mul(paramPointExt.y, arrayOfInt2, arrayOfInt2);
    F.normalize(arrayOfInt1);
    F.normalize(arrayOfInt2);
    int i = checkPoint(arrayOfInt1, arrayOfInt2);
    F.encode(arrayOfInt2, paramArrayOfbyte, paramInt);
    paramArrayOfbyte[paramInt + 57 - 1] = (byte)((arrayOfInt1[0] & 0x1) << 7);
    return i;
  }
  
  public static void generatePrivateKey(SecureRandom paramSecureRandom, byte[] paramArrayOfbyte) {
    paramSecureRandom.nextBytes(paramArrayOfbyte);
  }
  
  public static void generatePublicKey(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    Xof xof = createXof();
    byte[] arrayOfByte1 = new byte[114];
    xof.update(paramArrayOfbyte1, paramInt1, 57);
    xof.doFinal(arrayOfByte1, 0, arrayOfByte1.length);
    byte[] arrayOfByte2 = new byte[57];
    pruneScalar(arrayOfByte1, 0, arrayOfByte2);
    scalarMultBaseEncoded(arrayOfByte2, paramArrayOfbyte2, paramInt2);
  }
  
  private static int getWindow4(int[] paramArrayOfint, int paramInt) {
    int i = paramInt >>> 3;
    int j = (paramInt & 0x7) << 2;
    return paramArrayOfint[i] >>> j & 0xF;
  }
  
  private static byte[] getWnafVar(int[] paramArrayOfint, int paramInt) {
    int[] arrayOfInt = new int[28];
    int i = arrayOfInt.length;
    int j = 0;
    int k = 14;
    while (--k >= 0) {
      int n = paramArrayOfint[k];
      arrayOfInt[--i] = n >>> 16 | j << 16;
      arrayOfInt[--i] = j = n;
    } 
    byte[] arrayOfByte = new byte[447];
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
  
  private static void implSign(Xof paramXof, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, int paramInt1, byte[] paramArrayOfbyte4, byte paramByte, byte[] paramArrayOfbyte5, int paramInt2, int paramInt3, byte[] paramArrayOfbyte6, int paramInt4) {
    dom4(paramXof, paramByte, paramArrayOfbyte4);
    paramXof.update(paramArrayOfbyte1, 57, 57);
    paramXof.update(paramArrayOfbyte5, paramInt2, paramInt3);
    paramXof.doFinal(paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
    byte[] arrayOfByte1 = reduceScalar(paramArrayOfbyte1);
    byte[] arrayOfByte2 = new byte[57];
    scalarMultBaseEncoded(arrayOfByte1, arrayOfByte2, 0);
    dom4(paramXof, paramByte, paramArrayOfbyte4);
    paramXof.update(arrayOfByte2, 0, 57);
    paramXof.update(paramArrayOfbyte3, paramInt1, 57);
    paramXof.update(paramArrayOfbyte5, paramInt2, paramInt3);
    paramXof.doFinal(paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
    byte[] arrayOfByte3 = reduceScalar(paramArrayOfbyte1);
    byte[] arrayOfByte4 = calculateS(arrayOfByte1, arrayOfByte3, paramArrayOfbyte2);
    System.arraycopy(arrayOfByte2, 0, paramArrayOfbyte6, paramInt4, 57);
    System.arraycopy(arrayOfByte4, 0, paramArrayOfbyte6, paramInt4 + 57, 57);
  }
  
  private static void implSign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, byte paramByte, byte[] paramArrayOfbyte3, int paramInt2, int paramInt3, byte[] paramArrayOfbyte4, int paramInt4) {
    if (!checkContextVar(paramArrayOfbyte2))
      throw new IllegalArgumentException("ctx"); 
    Xof xof = createXof();
    byte[] arrayOfByte1 = new byte[114];
    xof.update(paramArrayOfbyte1, paramInt1, 57);
    xof.doFinal(arrayOfByte1, 0, arrayOfByte1.length);
    byte[] arrayOfByte2 = new byte[57];
    pruneScalar(arrayOfByte1, 0, arrayOfByte2);
    byte[] arrayOfByte3 = new byte[57];
    scalarMultBaseEncoded(arrayOfByte2, arrayOfByte3, 0);
    implSign(xof, arrayOfByte1, arrayOfByte2, arrayOfByte3, 0, paramArrayOfbyte2, paramByte, paramArrayOfbyte3, paramInt2, paramInt3, paramArrayOfbyte4, paramInt4);
  }
  
  private static void implSign(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte paramByte, byte[] paramArrayOfbyte4, int paramInt3, int paramInt4, byte[] paramArrayOfbyte5, int paramInt5) {
    if (!checkContextVar(paramArrayOfbyte3))
      throw new IllegalArgumentException("ctx"); 
    Xof xof = createXof();
    byte[] arrayOfByte1 = new byte[114];
    xof.update(paramArrayOfbyte1, paramInt1, 57);
    xof.doFinal(arrayOfByte1, 0, arrayOfByte1.length);
    byte[] arrayOfByte2 = new byte[57];
    pruneScalar(arrayOfByte1, 0, arrayOfByte2);
    implSign(xof, arrayOfByte1, arrayOfByte2, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, paramByte, paramArrayOfbyte4, paramInt3, paramInt4, paramArrayOfbyte5, paramInt5);
  }
  
  private static boolean implVerify(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte paramByte, byte[] paramArrayOfbyte4, int paramInt3, int paramInt4) {
    if (!checkContextVar(paramArrayOfbyte3))
      throw new IllegalArgumentException("ctx"); 
    byte[] arrayOfByte1 = copy(paramArrayOfbyte1, paramInt1, 57);
    byte[] arrayOfByte2 = copy(paramArrayOfbyte1, paramInt1 + 57, 57);
    if (!checkPointVar(arrayOfByte1))
      return false; 
    int[] arrayOfInt1 = new int[14];
    if (!checkScalarVar(arrayOfByte2, arrayOfInt1))
      return false; 
    PointExt pointExt1 = new PointExt();
    if (!decodePointVar(paramArrayOfbyte2, paramInt2, true, pointExt1))
      return false; 
    Xof xof = createXof();
    byte[] arrayOfByte3 = new byte[114];
    dom4(xof, paramByte, paramArrayOfbyte3);
    xof.update(arrayOfByte1, 0, 57);
    xof.update(paramArrayOfbyte2, paramInt2, 57);
    xof.update(paramArrayOfbyte4, paramInt3, paramInt4);
    xof.doFinal(arrayOfByte3, 0, arrayOfByte3.length);
    byte[] arrayOfByte4 = reduceScalar(arrayOfByte3);
    int[] arrayOfInt2 = new int[14];
    decodeScalar(arrayOfByte4, 0, arrayOfInt2);
    PointExt pointExt2 = new PointExt();
    scalarMultStrausVar(arrayOfInt1, arrayOfInt2, pointExt1, pointExt2);
    byte[] arrayOfByte5 = new byte[57];
    return (0 != encodePoint(pointExt2, arrayOfByte5, 0) && Arrays.areEqual(arrayOfByte5, arrayOfByte1));
  }
  
  private static boolean isNeutralElementVar(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    return (F.isZeroVar(paramArrayOfint1) && F.areEqualVar(paramArrayOfint2, paramArrayOfint3));
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
    F.mul(paramPointExt1.z, paramPointExt2.z, arrayOfInt1);
    F.sqr(arrayOfInt1, arrayOfInt2);
    F.mul(paramPointExt1.x, paramPointExt2.x, arrayOfInt3);
    F.mul(paramPointExt1.y, paramPointExt2.y, arrayOfInt4);
    F.mul(arrayOfInt3, arrayOfInt4, arrayOfInt5);
    F.mul(arrayOfInt5, 39081, arrayOfInt5);
    F.add(arrayOfInt2, arrayOfInt5, arrayOfInt6);
    F.sub(arrayOfInt2, arrayOfInt5, arrayOfInt7);
    F.add(paramPointExt1.x, paramPointExt1.y, arrayOfInt2);
    F.add(paramPointExt2.x, paramPointExt2.y, arrayOfInt5);
    F.mul(arrayOfInt2, arrayOfInt5, arrayOfInt8);
    F.add(arrayOfInt4, arrayOfInt3, arrayOfInt2);
    F.sub(arrayOfInt4, arrayOfInt3, arrayOfInt5);
    F.carry(arrayOfInt2);
    F.sub(arrayOfInt8, arrayOfInt2, arrayOfInt8);
    F.mul(arrayOfInt8, arrayOfInt1, arrayOfInt8);
    F.mul(arrayOfInt5, arrayOfInt1, arrayOfInt5);
    F.mul(arrayOfInt6, arrayOfInt8, paramPointExt2.x);
    F.mul(arrayOfInt5, arrayOfInt7, paramPointExt2.y);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointExt2.z);
  }
  
  private static void pointAddVar(boolean paramBoolean, PointExt paramPointExt1, PointExt paramPointExt2) {
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
      arrayOfInt9 = arrayOfInt5;
      arrayOfInt10 = arrayOfInt2;
      arrayOfInt11 = arrayOfInt7;
      arrayOfInt12 = arrayOfInt6;
      F.sub(paramPointExt1.y, paramPointExt1.x, arrayOfInt8);
    } else {
      arrayOfInt9 = arrayOfInt2;
      arrayOfInt10 = arrayOfInt5;
      arrayOfInt11 = arrayOfInt6;
      arrayOfInt12 = arrayOfInt7;
      F.add(paramPointExt1.y, paramPointExt1.x, arrayOfInt8);
    } 
    F.mul(paramPointExt1.z, paramPointExt2.z, arrayOfInt1);
    F.sqr(arrayOfInt1, arrayOfInt2);
    F.mul(paramPointExt1.x, paramPointExt2.x, arrayOfInt3);
    F.mul(paramPointExt1.y, paramPointExt2.y, arrayOfInt4);
    F.mul(arrayOfInt3, arrayOfInt4, arrayOfInt5);
    F.mul(arrayOfInt5, 39081, arrayOfInt5);
    F.add(arrayOfInt2, arrayOfInt5, arrayOfInt11);
    F.sub(arrayOfInt2, arrayOfInt5, arrayOfInt12);
    F.add(paramPointExt2.x, paramPointExt2.y, arrayOfInt5);
    F.mul(arrayOfInt8, arrayOfInt5, arrayOfInt8);
    F.add(arrayOfInt4, arrayOfInt3, arrayOfInt9);
    F.sub(arrayOfInt4, arrayOfInt3, arrayOfInt10);
    F.carry(arrayOfInt9);
    F.sub(arrayOfInt8, arrayOfInt2, arrayOfInt8);
    F.mul(arrayOfInt8, arrayOfInt1, arrayOfInt8);
    F.mul(arrayOfInt5, arrayOfInt1, arrayOfInt5);
    F.mul(arrayOfInt6, arrayOfInt8, paramPointExt2.x);
    F.mul(arrayOfInt5, arrayOfInt7, paramPointExt2.y);
    F.mul(arrayOfInt6, arrayOfInt7, paramPointExt2.z);
  }
  
  private static void pointAddPrecomp(PointPrecomp paramPointPrecomp, PointExt paramPointExt) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = F.create();
    int[] arrayOfInt5 = F.create();
    int[] arrayOfInt6 = F.create();
    int[] arrayOfInt7 = F.create();
    F.sqr(paramPointExt.z, arrayOfInt1);
    F.mul(paramPointPrecomp.x, paramPointExt.x, arrayOfInt2);
    F.mul(paramPointPrecomp.y, paramPointExt.y, arrayOfInt3);
    F.mul(arrayOfInt2, arrayOfInt3, arrayOfInt4);
    F.mul(arrayOfInt4, 39081, arrayOfInt4);
    F.add(arrayOfInt1, arrayOfInt4, arrayOfInt5);
    F.sub(arrayOfInt1, arrayOfInt4, arrayOfInt6);
    F.add(paramPointPrecomp.x, paramPointPrecomp.y, arrayOfInt1);
    F.add(paramPointExt.x, paramPointExt.y, arrayOfInt4);
    F.mul(arrayOfInt1, arrayOfInt4, arrayOfInt7);
    F.add(arrayOfInt3, arrayOfInt2, arrayOfInt1);
    F.sub(arrayOfInt3, arrayOfInt2, arrayOfInt4);
    F.carry(arrayOfInt1);
    F.sub(arrayOfInt7, arrayOfInt1, arrayOfInt7);
    F.mul(arrayOfInt7, paramPointExt.z, arrayOfInt7);
    F.mul(arrayOfInt4, paramPointExt.z, arrayOfInt4);
    F.mul(arrayOfInt5, arrayOfInt7, paramPointExt.x);
    F.mul(arrayOfInt4, arrayOfInt6, paramPointExt.y);
    F.mul(arrayOfInt5, arrayOfInt6, paramPointExt.z);
  }
  
  private static PointExt pointCopy(PointExt paramPointExt) {
    PointExt pointExt = new PointExt();
    pointCopy(paramPointExt, pointExt);
    return pointExt;
  }
  
  private static void pointCopy(PointExt paramPointExt1, PointExt paramPointExt2) {
    F.copy(paramPointExt1.x, 0, paramPointExt2.x, 0);
    F.copy(paramPointExt1.y, 0, paramPointExt2.y, 0);
    F.copy(paramPointExt1.z, 0, paramPointExt2.z, 0);
  }
  
  private static void pointDouble(PointExt paramPointExt) {
    int[] arrayOfInt1 = F.create();
    int[] arrayOfInt2 = F.create();
    int[] arrayOfInt3 = F.create();
    int[] arrayOfInt4 = F.create();
    int[] arrayOfInt5 = F.create();
    int[] arrayOfInt6 = F.create();
    F.add(paramPointExt.x, paramPointExt.y, arrayOfInt1);
    F.sqr(arrayOfInt1, arrayOfInt1);
    F.sqr(paramPointExt.x, arrayOfInt2);
    F.sqr(paramPointExt.y, arrayOfInt3);
    F.add(arrayOfInt2, arrayOfInt3, arrayOfInt4);
    F.carry(arrayOfInt4);
    F.sqr(paramPointExt.z, arrayOfInt5);
    F.add(arrayOfInt5, arrayOfInt5, arrayOfInt5);
    F.carry(arrayOfInt5);
    F.sub(arrayOfInt4, arrayOfInt5, arrayOfInt6);
    F.sub(arrayOfInt1, arrayOfInt4, arrayOfInt1);
    F.sub(arrayOfInt2, arrayOfInt3, arrayOfInt2);
    F.mul(arrayOfInt1, arrayOfInt6, paramPointExt.x);
    F.mul(arrayOfInt4, arrayOfInt2, paramPointExt.y);
    F.mul(arrayOfInt4, arrayOfInt6, paramPointExt.z);
  }
  
  private static void pointExtendXY(PointExt paramPointExt) {
    F.one(paramPointExt.z);
  }
  
  private static void pointLookup(int paramInt1, int paramInt2, PointPrecomp paramPointPrecomp) {
    int i = paramInt1 * 16 * 2 * 16;
    for (byte b = 0; b < 16; b++) {
      int j = (b ^ paramInt2) - 1 >> 31;
      F.cmov(j, precompBase, i, paramPointPrecomp.x, 0);
      i += 16;
      F.cmov(j, precompBase, i, paramPointPrecomp.y, 0);
      i += 16;
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
      b++;
    } 
    F.cnegate(j, paramPointExt.x);
  }
  
  private static int[] pointPrecompute(PointExt paramPointExt, int paramInt) {
    PointExt pointExt1 = pointCopy(paramPointExt);
    PointExt pointExt2 = pointCopy(pointExt1);
    pointDouble(pointExt2);
    int[] arrayOfInt = F.createTable(paramInt * 3);
    boolean bool = false;
    byte b = 0;
    while (true) {
      F.copy(pointExt1.x, 0, arrayOfInt, bool);
      bool += true;
      F.copy(pointExt1.y, 0, arrayOfInt, bool);
      bool += true;
      F.copy(pointExt1.z, 0, arrayOfInt, bool);
      bool += true;
      if (++b == paramInt)
        return arrayOfInt; 
      pointAdd(pointExt2, pointExt1);
    } 
  }
  
  private static PointExt[] pointPrecomputeVar(PointExt paramPointExt, int paramInt) {
    PointExt pointExt = pointCopy(paramPointExt);
    pointDouble(pointExt);
    PointExt[] arrayOfPointExt = new PointExt[paramInt];
    arrayOfPointExt[0] = pointCopy(paramPointExt);
    for (byte b = 1; b < paramInt; b++) {
      arrayOfPointExt[b] = pointCopy(arrayOfPointExt[b - 1]);
      pointAddVar(false, pointExt, arrayOfPointExt[b]);
    } 
    return arrayOfPointExt;
  }
  
  private static void pointSetNeutral(PointExt paramPointExt) {
    F.zero(paramPointExt.x);
    F.one(paramPointExt.y);
    F.one(paramPointExt.z);
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
      precompBase = F.createTable(160);
      boolean bool = false;
      for (byte b = 0; b < 5; b++) {
        PointExt[] arrayOfPointExt1 = new PointExt[5];
        PointExt pointExt1 = new PointExt();
        pointSetNeutral(pointExt1);
        for (byte b1 = 0; b1 < 5; b1++) {
          pointAddVar(true, pointExt, pointExt1);
          pointDouble(pointExt);
          arrayOfPointExt1[b1] = pointCopy(pointExt);
          if (b + b1 != 8)
            for (byte b6 = 1; b6 < 18; b6++)
              pointDouble(pointExt);  
        } 
        PointExt[] arrayOfPointExt2 = new PointExt[16];
        byte b2 = 0;
        arrayOfPointExt2[b2++] = pointExt1;
        for (byte b3 = 0; b3 < 4; b3++) {
          int i = 1 << b3;
          byte b6 = 0;
          while (b6 < i) {
            arrayOfPointExt2[b2] = pointCopy(arrayOfPointExt2[b2 - i]);
            pointAddVar(false, arrayOfPointExt1[b3], arrayOfPointExt2[b2]);
            b6++;
            b2++;
          } 
        } 
        int[] arrayOfInt1 = F.createTable(16);
        int[] arrayOfInt2 = F.create();
        F.copy((arrayOfPointExt2[0]).z, 0, arrayOfInt2, 0);
        F.copy(arrayOfInt2, 0, arrayOfInt1, 0);
        byte b5 = 0;
        while (++b5 < 16) {
          F.mul(arrayOfInt2, (arrayOfPointExt2[b5]).z, arrayOfInt2);
          F.copy(arrayOfInt2, 0, arrayOfInt1, b5 * 16);
        } 
        F.invVar(arrayOfInt2, arrayOfInt2);
        b5--;
        int[] arrayOfInt3 = F.create();
        while (b5 > 0) {
          byte b6 = b5--;
          F.copy(arrayOfInt1, b5 * 16, arrayOfInt3, 0);
          F.mul(arrayOfInt3, arrayOfInt2, arrayOfInt3);
          F.copy(arrayOfInt3, 0, arrayOfInt1, b6 * 16);
          F.mul(arrayOfInt2, (arrayOfPointExt2[b6]).z, arrayOfInt2);
        } 
        F.copy(arrayOfInt2, 0, arrayOfInt1, 0);
        for (byte b4 = 0; b4 < 16; b4++) {
          PointExt pointExt2 = arrayOfPointExt2[b4];
          F.copy(arrayOfInt1, b4 * 16, pointExt2.z, 0);
          F.mul(pointExt2.x, pointExt2.z, pointExt2.x);
          F.mul(pointExt2.y, pointExt2.z, pointExt2.y);
          F.copy(pointExt2.x, 0, precompBase, bool);
          bool += true;
          F.copy(pointExt2.y, 0, precompBase, bool);
          bool += true;
        } 
      } 
    } 
  }
  
  private static void pruneScalar(byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2) {
    System.arraycopy(paramArrayOfbyte1, paramInt, paramArrayOfbyte2, 0, 56);
    paramArrayOfbyte2[0] = (byte)(paramArrayOfbyte2[0] & 0xFC);
    paramArrayOfbyte2[55] = (byte)(paramArrayOfbyte2[55] | 0x80);
    paramArrayOfbyte2[56] = 0;
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
    long l19 = decode32(paramArrayOfbyte, 63) & 0xFFFFFFFFL;
    long l20 = (decode24(paramArrayOfbyte, 67) << 4) & 0xFFFFFFFFL;
    long l21 = decode32(paramArrayOfbyte, 70) & 0xFFFFFFFFL;
    long l22 = (decode24(paramArrayOfbyte, 74) << 4) & 0xFFFFFFFFL;
    long l23 = decode32(paramArrayOfbyte, 77) & 0xFFFFFFFFL;
    long l24 = (decode24(paramArrayOfbyte, 81) << 4) & 0xFFFFFFFFL;
    long l25 = decode32(paramArrayOfbyte, 84) & 0xFFFFFFFFL;
    long l26 = (decode24(paramArrayOfbyte, 88) << 4) & 0xFFFFFFFFL;
    long l27 = decode32(paramArrayOfbyte, 91) & 0xFFFFFFFFL;
    long l28 = (decode24(paramArrayOfbyte, 95) << 4) & 0xFFFFFFFFL;
    long l29 = decode32(paramArrayOfbyte, 98) & 0xFFFFFFFFL;
    long l30 = (decode24(paramArrayOfbyte, 102) << 4) & 0xFFFFFFFFL;
    long l31 = decode32(paramArrayOfbyte, 105) & 0xFFFFFFFFL;
    long l32 = (decode24(paramArrayOfbyte, 109) << 4) & 0xFFFFFFFFL;
    long l33 = decode16(paramArrayOfbyte, 112) & 0xFFFFFFFFL;
    l17 += l33 * 43969588L;
    l18 += l33 * 30366549L;
    l19 += l33 * 163752818L;
    l20 += l33 * 258169998L;
    l21 += l33 * 96434764L;
    l22 += l33 * 227822194L;
    l23 += l33 * 149865618L;
    l24 += l33 * 550336261L;
    l32 += l31 >>> 28L;
    l31 &= 0xFFFFFFFL;
    l16 += l32 * 43969588L;
    l17 += l32 * 30366549L;
    l18 += l32 * 163752818L;
    l19 += l32 * 258169998L;
    l20 += l32 * 96434764L;
    l21 += l32 * 227822194L;
    l22 += l32 * 149865618L;
    l23 += l32 * 550336261L;
    l15 += l31 * 43969588L;
    l16 += l31 * 30366549L;
    l17 += l31 * 163752818L;
    l18 += l31 * 258169998L;
    l19 += l31 * 96434764L;
    l20 += l31 * 227822194L;
    l21 += l31 * 149865618L;
    l22 += l31 * 550336261L;
    l30 += l29 >>> 28L;
    l29 &= 0xFFFFFFFL;
    l14 += l30 * 43969588L;
    l15 += l30 * 30366549L;
    l16 += l30 * 163752818L;
    l17 += l30 * 258169998L;
    l18 += l30 * 96434764L;
    l19 += l30 * 227822194L;
    l20 += l30 * 149865618L;
    l21 += l30 * 550336261L;
    l13 += l29 * 43969588L;
    l14 += l29 * 30366549L;
    l15 += l29 * 163752818L;
    l16 += l29 * 258169998L;
    l17 += l29 * 96434764L;
    l18 += l29 * 227822194L;
    l19 += l29 * 149865618L;
    l20 += l29 * 550336261L;
    l28 += l27 >>> 28L;
    l27 &= 0xFFFFFFFL;
    l12 += l28 * 43969588L;
    l13 += l28 * 30366549L;
    l14 += l28 * 163752818L;
    l15 += l28 * 258169998L;
    l16 += l28 * 96434764L;
    l17 += l28 * 227822194L;
    l18 += l28 * 149865618L;
    l19 += l28 * 550336261L;
    l11 += l27 * 43969588L;
    l12 += l27 * 30366549L;
    l13 += l27 * 163752818L;
    l14 += l27 * 258169998L;
    l15 += l27 * 96434764L;
    l16 += l27 * 227822194L;
    l17 += l27 * 149865618L;
    l18 += l27 * 550336261L;
    l26 += l25 >>> 28L;
    l25 &= 0xFFFFFFFL;
    l10 += l26 * 43969588L;
    l11 += l26 * 30366549L;
    l12 += l26 * 163752818L;
    l13 += l26 * 258169998L;
    l14 += l26 * 96434764L;
    l15 += l26 * 227822194L;
    l16 += l26 * 149865618L;
    l17 += l26 * 550336261L;
    l22 += l21 >>> 28L;
    l21 &= 0xFFFFFFFL;
    l23 += l22 >>> 28L;
    l22 &= 0xFFFFFFFL;
    l24 += l23 >>> 28L;
    l23 &= 0xFFFFFFFL;
    l25 += l24 >>> 28L;
    l24 &= 0xFFFFFFFL;
    l9 += l25 * 43969588L;
    l10 += l25 * 30366549L;
    l11 += l25 * 163752818L;
    l12 += l25 * 258169998L;
    l13 += l25 * 96434764L;
    l14 += l25 * 227822194L;
    l15 += l25 * 149865618L;
    l16 += l25 * 550336261L;
    l8 += l24 * 43969588L;
    l9 += l24 * 30366549L;
    l10 += l24 * 163752818L;
    l11 += l24 * 258169998L;
    l12 += l24 * 96434764L;
    l13 += l24 * 227822194L;
    l14 += l24 * 149865618L;
    l15 += l24 * 550336261L;
    l7 += l23 * 43969588L;
    l8 += l23 * 30366549L;
    l9 += l23 * 163752818L;
    l10 += l23 * 258169998L;
    l11 += l23 * 96434764L;
    l12 += l23 * 227822194L;
    l13 += l23 * 149865618L;
    l14 += l23 * 550336261L;
    l19 += l18 >>> 28L;
    l18 &= 0xFFFFFFFL;
    l20 += l19 >>> 28L;
    l19 &= 0xFFFFFFFL;
    l21 += l20 >>> 28L;
    l20 &= 0xFFFFFFFL;
    l22 += l21 >>> 28L;
    l21 &= 0xFFFFFFFL;
    l6 += l22 * 43969588L;
    l7 += l22 * 30366549L;
    l8 += l22 * 163752818L;
    l9 += l22 * 258169998L;
    l10 += l22 * 96434764L;
    l11 += l22 * 227822194L;
    l12 += l22 * 149865618L;
    l13 += l22 * 550336261L;
    l5 += l21 * 43969588L;
    l6 += l21 * 30366549L;
    l7 += l21 * 163752818L;
    l8 += l21 * 258169998L;
    l9 += l21 * 96434764L;
    l10 += l21 * 227822194L;
    l11 += l21 * 149865618L;
    l12 += l21 * 550336261L;
    l4 += l20 * 43969588L;
    l5 += l20 * 30366549L;
    l6 += l20 * 163752818L;
    l7 += l20 * 258169998L;
    l8 += l20 * 96434764L;
    l9 += l20 * 227822194L;
    l10 += l20 * 149865618L;
    l11 += l20 * 550336261L;
    l16 += l15 >>> 28L;
    l15 &= 0xFFFFFFFL;
    l17 += l16 >>> 28L;
    l16 &= 0xFFFFFFFL;
    l18 += l17 >>> 28L;
    l17 &= 0xFFFFFFFL;
    l19 += l18 >>> 28L;
    l18 &= 0xFFFFFFFL;
    l3 += l19 * 43969588L;
    l4 += l19 * 30366549L;
    l5 += l19 * 163752818L;
    l6 += l19 * 258169998L;
    l7 += l19 * 96434764L;
    l8 += l19 * 227822194L;
    l9 += l19 * 149865618L;
    l10 += l19 * 550336261L;
    l2 += l18 * 43969588L;
    l3 += l18 * 30366549L;
    l4 += l18 * 163752818L;
    l5 += l18 * 258169998L;
    l6 += l18 * 96434764L;
    l7 += l18 * 227822194L;
    l8 += l18 * 149865618L;
    l9 += l18 * 550336261L;
    l17 *= 4L;
    l17 += l16 >>> 26L;
    l16 &= 0x3FFFFFFL;
    l17++;
    l1 += l17 * 78101261L;
    l2 += l17 * 141809365L;
    l3 += l17 * 175155932L;
    l4 += l17 * 64542499L;
    l5 += l17 * 158326419L;
    l6 += l17 * 191173276L;
    l7 += l17 * 104575268L;
    l8 += l17 * 137584065L;
    l2 += l1 >>> 28L;
    l1 &= 0xFFFFFFFL;
    l3 += l2 >>> 28L;
    l2 &= 0xFFFFFFFL;
    l4 += l3 >>> 28L;
    l3 &= 0xFFFFFFFL;
    l5 += l4 >>> 28L;
    l4 &= 0xFFFFFFFL;
    l6 += l5 >>> 28L;
    l5 &= 0xFFFFFFFL;
    l7 += l6 >>> 28L;
    l6 &= 0xFFFFFFFL;
    l8 += l7 >>> 28L;
    l7 &= 0xFFFFFFFL;
    l9 += l8 >>> 28L;
    l8 &= 0xFFFFFFFL;
    l10 += l9 >>> 28L;
    l9 &= 0xFFFFFFFL;
    l11 += l10 >>> 28L;
    l10 &= 0xFFFFFFFL;
    l12 += l11 >>> 28L;
    l11 &= 0xFFFFFFFL;
    l13 += l12 >>> 28L;
    l12 &= 0xFFFFFFFL;
    l14 += l13 >>> 28L;
    l13 &= 0xFFFFFFFL;
    l15 += l14 >>> 28L;
    l14 &= 0xFFFFFFFL;
    l16 += l15 >>> 28L;
    l15 &= 0xFFFFFFFL;
    l17 = l16 >>> 26L;
    l16 &= 0x3FFFFFFL;
    l17--;
    l1 -= l17 & 0x4A7BB0DL;
    l2 -= l17 & 0x873D6D5L;
    l3 -= l17 & 0xA70AADCL;
    l4 -= l17 & 0x3D8D723L;
    l5 -= l17 & 0x96FDE93L;
    l6 -= l17 & 0xB65129CL;
    l7 -= l17 & 0x63BB124L;
    l8 -= l17 & 0x8335DC1L;
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
    l10 += l9 >> 28L;
    l9 &= 0xFFFFFFFL;
    l11 += l10 >> 28L;
    l10 &= 0xFFFFFFFL;
    l12 += l11 >> 28L;
    l11 &= 0xFFFFFFFL;
    l13 += l12 >> 28L;
    l12 &= 0xFFFFFFFL;
    l14 += l13 >> 28L;
    l13 &= 0xFFFFFFFL;
    l15 += l14 >> 28L;
    l14 &= 0xFFFFFFFL;
    l16 += l15 >> 28L;
    l15 &= 0xFFFFFFFL;
    byte[] arrayOfByte = new byte[57];
    encode56(l1 | l2 << 28L, arrayOfByte, 0);
    encode56(l3 | l4 << 28L, arrayOfByte, 7);
    encode56(l5 | l6 << 28L, arrayOfByte, 14);
    encode56(l7 | l8 << 28L, arrayOfByte, 21);
    encode56(l9 | l10 << 28L, arrayOfByte, 28);
    encode56(l11 | l12 << 28L, arrayOfByte, 35);
    encode56(l13 | l14 << 28L, arrayOfByte, 42);
    encode56(l15 | l16 << 28L, arrayOfByte, 49);
    return arrayOfByte;
  }
  
  private static void scalarMult(byte[] paramArrayOfbyte, PointExt paramPointExt1, PointExt paramPointExt2) {
    int[] arrayOfInt1 = new int[14];
    decodeScalar(paramArrayOfbyte, 0, arrayOfInt1);
    Nat.shiftDownBits(14, arrayOfInt1, 2, 0);
    Nat.cadd(14, (arrayOfInt1[0] ^ 0xFFFFFFFF) & 0x1, arrayOfInt1, L, arrayOfInt1);
    Nat.shiftDownBit(14, arrayOfInt1, 1);
    int[] arrayOfInt2 = pointPrecompute(paramPointExt1, 8);
    PointExt pointExt = new PointExt();
    pointLookup(arrayOfInt1, 111, arrayOfInt2, paramPointExt2);
    byte b;
    for (b = 110; b >= 0; b--) {
      for (byte b1 = 0; b1 < 4; b1++)
        pointDouble(paramPointExt2); 
      pointLookup(arrayOfInt1, b, arrayOfInt2, pointExt);
      pointAdd(pointExt, paramPointExt2);
    } 
    for (b = 0; b < 2; b++)
      pointDouble(paramPointExt2); 
  }
  
  private static void scalarMultBase(byte[] paramArrayOfbyte, PointExt paramPointExt) {
    precompute();
    int[] arrayOfInt = new int[15];
    decodeScalar(paramArrayOfbyte, 0, arrayOfInt);
    arrayOfInt[14] = 4 + Nat.cadd(14, (arrayOfInt[0] ^ 0xFFFFFFFF) & 0x1, arrayOfInt, L, arrayOfInt);
    Nat.shiftDownBit(arrayOfInt.length, arrayOfInt, 0);
    PointPrecomp pointPrecomp = new PointPrecomp();
    pointSetNeutral(paramPointExt);
    byte b = 17;
    while (true) {
      byte b1 = b;
      for (byte b2 = 0; b2 < 5; b2++) {
        int i = 0;
        int j;
        for (j = 0; j < 5; j++) {
          int m = arrayOfInt[b1 >>> 5] >>> (b1 & 0x1F);
          i &= 1 << j ^ 0xFFFFFFFF;
          i ^= m << j;
          b1 += 18;
        } 
        j = i >>> 4 & 0x1;
        int k = (i ^ -j) & 0xF;
        pointLookup(b2, k, pointPrecomp);
        F.cnegate(j, pointPrecomp.x);
        pointAddPrecomp(pointPrecomp, paramPointExt);
      } 
      if (--b < 0)
        break; 
      pointDouble(paramPointExt);
    } 
  }
  
  private static void scalarMultBaseEncoded(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    PointExt pointExt = new PointExt();
    scalarMultBase(paramArrayOfbyte1, pointExt);
    if (0 == encodePoint(pointExt, paramArrayOfbyte2, paramInt))
      throw new IllegalStateException(); 
  }
  
  public static void scalarMultBaseXY(X448.Friend paramFriend, byte[] paramArrayOfbyte, int paramInt, int[] paramArrayOfint1, int[] paramArrayOfint2) {
    if (null == paramFriend)
      throw new NullPointerException("This method is only for use by X448"); 
    byte[] arrayOfByte = new byte[57];
    pruneScalar(paramArrayOfbyte, paramInt, arrayOfByte);
    PointExt pointExt = new PointExt();
    scalarMultBase(arrayOfByte, pointExt);
    if (0 == checkPoint(pointExt.x, pointExt.y, pointExt.z))
      throw new IllegalStateException(); 
    F.copy(pointExt.x, 0, paramArrayOfint1, 0);
    F.copy(pointExt.y, 0, paramArrayOfint2, 0);
  }
  
  private static void scalarMultOrderVar(PointExt paramPointExt1, PointExt paramPointExt2) {
    byte[] arrayOfByte = getWnafVar(L, 5);
    PointExt[] arrayOfPointExt = pointPrecomputeVar(paramPointExt1, 8);
    pointSetNeutral(paramPointExt2);
    char c = 'ƾ';
    while (true) {
      byte b = arrayOfByte[c];
      if (b != 0) {
        int i = b >> 31;
        int j = (b ^ i) >>> 1;
        pointAddVar((i != 0), arrayOfPointExt[j], paramPointExt2);
      } 
      if (--c < '\000')
        break; 
      pointDouble(paramPointExt2);
    } 
  }
  
  private static void scalarMultStrausVar(int[] paramArrayOfint1, int[] paramArrayOfint2, PointExt paramPointExt1, PointExt paramPointExt2) {
    precompute();
    byte[] arrayOfByte1 = getWnafVar(paramArrayOfint1, 7);
    byte[] arrayOfByte2 = getWnafVar(paramArrayOfint2, 5);
    PointExt[] arrayOfPointExt = pointPrecomputeVar(paramPointExt1, 8);
    pointSetNeutral(paramPointExt2);
    char c = 'ƾ';
    while (true) {
      byte b1 = arrayOfByte1[c];
      if (b1 != 0) {
        int i = b1 >> 31;
        int j = (b1 ^ i) >>> 1;
        pointAddVar((i != 0), precompBaseTable[j], paramPointExt2);
      } 
      byte b2 = arrayOfByte2[c];
      if (b2 != 0) {
        int i = b2 >> 31;
        int j = (b2 ^ i) >>> 1;
        pointAddVar((i != 0), arrayOfPointExt[j], paramPointExt2);
      } 
      if (--c < '\000')
        break; 
      pointDouble(paramPointExt2);
    } 
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
  
  public static void signPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, Xof paramXof, byte[] paramArrayOfbyte3, int paramInt2) {
    byte[] arrayOfByte = new byte[64];
    if (64 != paramXof.doFinal(arrayOfByte, 0, 64))
      throw new IllegalArgumentException("ph"); 
    boolean bool = true;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, bool, arrayOfByte, 0, arrayOfByte.length, paramArrayOfbyte3, paramInt2);
  }
  
  public static void signPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, Xof paramXof, byte[] paramArrayOfbyte4, int paramInt3) {
    byte[] arrayOfByte = new byte[64];
    if (64 != paramXof.doFinal(arrayOfByte, 0, 64))
      throw new IllegalArgumentException("ph"); 
    boolean bool = true;
    implSign(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, arrayOfByte, 0, arrayOfByte.length, paramArrayOfbyte4, paramInt3);
  }
  
  public static boolean validatePublicKeyFull(byte[] paramArrayOfbyte, int paramInt) {
    PointExt pointExt1 = new PointExt();
    if (!decodePointVar(paramArrayOfbyte, paramInt, false, pointExt1))
      return false; 
    F.normalize(pointExt1.x);
    F.normalize(pointExt1.y);
    F.normalize(pointExt1.z);
    if (isNeutralElementVar(pointExt1.x, pointExt1.y, pointExt1.z))
      return false; 
    PointExt pointExt2 = new PointExt();
    scalarMultOrderVar(pointExt1, pointExt2);
    F.normalize(pointExt2.x);
    F.normalize(pointExt2.y);
    F.normalize(pointExt2.z);
    return isNeutralElementVar(pointExt2.x, pointExt2.y, pointExt2.z);
  }
  
  public static boolean validatePublicKeyPartial(byte[] paramArrayOfbyte, int paramInt) {
    PointExt pointExt = new PointExt();
    return decodePointVar(paramArrayOfbyte, paramInt, false, pointExt);
  }
  
  public static boolean verify(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, int paramInt3, int paramInt4) {
    boolean bool = false;
    return implVerify(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, paramArrayOfbyte4, paramInt3, paramInt4);
  }
  
  public static boolean verifyPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4, int paramInt3) {
    boolean bool = true;
    return implVerify(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, paramArrayOfbyte4, paramInt3, 64);
  }
  
  public static boolean verifyPrehash(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2, byte[] paramArrayOfbyte3, Xof paramXof) {
    byte[] arrayOfByte = new byte[64];
    if (64 != paramXof.doFinal(arrayOfByte, 0, 64))
      throw new IllegalArgumentException("ph"); 
    boolean bool = true;
    return implVerify(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2, paramArrayOfbyte3, bool, arrayOfByte, 0, arrayOfByte.length);
  }
  
  public static final class Algorithm {
    public static final int Ed448 = 0;
    
    public static final int Ed448ph = 1;
  }
  
  private static class F extends X448Field {}
  
  private static class PointExt {
    int[] x = Ed448.F.create();
    
    int[] y = Ed448.F.create();
    
    int[] z = Ed448.F.create();
    
    private PointExt() {}
  }
  
  private static class PointPrecomp {
    int[] x = Ed448.F.create();
    
    int[] y = Ed448.F.create();
    
    private PointPrecomp() {}
  }
}
