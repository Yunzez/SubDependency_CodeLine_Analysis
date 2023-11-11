package META-INF.versions.9.org.bouncycastle.math.raw;

import java.math.BigInteger;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Pack;

public abstract class Nat256 {
  private static final long M = 4294967295L;
  
  public static int add(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    long l = 0L;
    l += (paramArrayOfint1[0] & 0xFFFFFFFFL) + (paramArrayOfint2[0] & 0xFFFFFFFFL);
    paramArrayOfint3[0] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[1] & 0xFFFFFFFFL) + (paramArrayOfint2[1] & 0xFFFFFFFFL);
    paramArrayOfint3[1] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[2] & 0xFFFFFFFFL) + (paramArrayOfint2[2] & 0xFFFFFFFFL);
    paramArrayOfint3[2] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[3] & 0xFFFFFFFFL) + (paramArrayOfint2[3] & 0xFFFFFFFFL);
    paramArrayOfint3[3] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[4] & 0xFFFFFFFFL) + (paramArrayOfint2[4] & 0xFFFFFFFFL);
    paramArrayOfint3[4] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[5] & 0xFFFFFFFFL) + (paramArrayOfint2[5] & 0xFFFFFFFFL);
    paramArrayOfint3[5] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[6] & 0xFFFFFFFFL) + (paramArrayOfint2[6] & 0xFFFFFFFFL);
    paramArrayOfint3[6] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[7] & 0xFFFFFFFFL) + (paramArrayOfint2[7] & 0xFFFFFFFFL);
    paramArrayOfint3[7] = (int)l;
    l >>>= 32L;
    return (int)l;
  }
  
  public static int add(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2, int[] paramArrayOfint3, int paramInt3) {
    long l = 0L;
    l += (paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 0] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 1] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 1] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 2] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 2] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 3] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 3] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 4] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 4] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 5] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 5] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 6] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 6] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 7] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 7] = (int)l;
    l >>>= 32L;
    return (int)l;
  }
  
  public static int addBothTo(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    long l = 0L;
    l += (paramArrayOfint1[0] & 0xFFFFFFFFL) + (paramArrayOfint2[0] & 0xFFFFFFFFL) + (paramArrayOfint3[0] & 0xFFFFFFFFL);
    paramArrayOfint3[0] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[1] & 0xFFFFFFFFL) + (paramArrayOfint2[1] & 0xFFFFFFFFL) + (paramArrayOfint3[1] & 0xFFFFFFFFL);
    paramArrayOfint3[1] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[2] & 0xFFFFFFFFL) + (paramArrayOfint2[2] & 0xFFFFFFFFL) + (paramArrayOfint3[2] & 0xFFFFFFFFL);
    paramArrayOfint3[2] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[3] & 0xFFFFFFFFL) + (paramArrayOfint2[3] & 0xFFFFFFFFL) + (paramArrayOfint3[3] & 0xFFFFFFFFL);
    paramArrayOfint3[3] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[4] & 0xFFFFFFFFL) + (paramArrayOfint2[4] & 0xFFFFFFFFL) + (paramArrayOfint3[4] & 0xFFFFFFFFL);
    paramArrayOfint3[4] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[5] & 0xFFFFFFFFL) + (paramArrayOfint2[5] & 0xFFFFFFFFL) + (paramArrayOfint3[5] & 0xFFFFFFFFL);
    paramArrayOfint3[5] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[6] & 0xFFFFFFFFL) + (paramArrayOfint2[6] & 0xFFFFFFFFL) + (paramArrayOfint3[6] & 0xFFFFFFFFL);
    paramArrayOfint3[6] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[7] & 0xFFFFFFFFL) + (paramArrayOfint2[7] & 0xFFFFFFFFL) + (paramArrayOfint3[7] & 0xFFFFFFFFL);
    paramArrayOfint3[7] = (int)l;
    l >>>= 32L;
    return (int)l;
  }
  
  public static int addBothTo(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2, int[] paramArrayOfint3, int paramInt3) {
    long l = 0L;
    l += (paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 0] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 0] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 1] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 1] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 1] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 2] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 2] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 2] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 3] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 3] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 3] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 4] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 4] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 4] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 5] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 5] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 5] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 6] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 6] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 6] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 7] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL) + (paramArrayOfint3[paramInt3 + 7] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 7] = (int)l;
    l >>>= 32L;
    return (int)l;
  }
  
  public static int addTo(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    long l = 0L;
    l += (paramArrayOfint1[0] & 0xFFFFFFFFL) + (paramArrayOfint2[0] & 0xFFFFFFFFL);
    paramArrayOfint2[0] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[1] & 0xFFFFFFFFL) + (paramArrayOfint2[1] & 0xFFFFFFFFL);
    paramArrayOfint2[1] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[2] & 0xFFFFFFFFL) + (paramArrayOfint2[2] & 0xFFFFFFFFL);
    paramArrayOfint2[2] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[3] & 0xFFFFFFFFL) + (paramArrayOfint2[3] & 0xFFFFFFFFL);
    paramArrayOfint2[3] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[4] & 0xFFFFFFFFL) + (paramArrayOfint2[4] & 0xFFFFFFFFL);
    paramArrayOfint2[4] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[5] & 0xFFFFFFFFL) + (paramArrayOfint2[5] & 0xFFFFFFFFL);
    paramArrayOfint2[5] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[6] & 0xFFFFFFFFL) + (paramArrayOfint2[6] & 0xFFFFFFFFL);
    paramArrayOfint2[6] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[7] & 0xFFFFFFFFL) + (paramArrayOfint2[7] & 0xFFFFFFFFL);
    paramArrayOfint2[7] = (int)l;
    l >>>= 32L;
    return (int)l;
  }
  
  public static int addTo(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2, int paramInt3) {
    long l = paramInt3 & 0xFFFFFFFFL;
    l += (paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 0] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 1] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 1] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 2] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 2] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 3] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 3] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 4] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 4] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 5] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 5] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 6] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 6] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 7] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 7] = (int)l;
    l >>>= 32L;
    return (int)l;
  }
  
  public static int addToEachOther(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    long l = 0L;
    l += (paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 0] = (int)l;
    paramArrayOfint2[paramInt2 + 0] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 1] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 1] = (int)l;
    paramArrayOfint2[paramInt2 + 1] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 2] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 2] = (int)l;
    paramArrayOfint2[paramInt2 + 2] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 3] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 3] = (int)l;
    paramArrayOfint2[paramInt2 + 3] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 4] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 4] = (int)l;
    paramArrayOfint2[paramInt2 + 4] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 5] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 5] = (int)l;
    paramArrayOfint2[paramInt2 + 5] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 6] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 6] = (int)l;
    paramArrayOfint2[paramInt2 + 6] = (int)l;
    l >>>= 32L;
    l += (paramArrayOfint1[paramInt1 + 7] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL);
    paramArrayOfint1[paramInt1 + 7] = (int)l;
    paramArrayOfint2[paramInt2 + 7] = (int)l;
    l >>>= 32L;
    return (int)l;
  }
  
  public static void copy(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    paramArrayOfint2[0] = paramArrayOfint1[0];
    paramArrayOfint2[1] = paramArrayOfint1[1];
    paramArrayOfint2[2] = paramArrayOfint1[2];
    paramArrayOfint2[3] = paramArrayOfint1[3];
    paramArrayOfint2[4] = paramArrayOfint1[4];
    paramArrayOfint2[5] = paramArrayOfint1[5];
    paramArrayOfint2[6] = paramArrayOfint1[6];
    paramArrayOfint2[7] = paramArrayOfint1[7];
  }
  
  public static void copy(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    paramArrayOfint2[paramInt2 + 0] = paramArrayOfint1[paramInt1 + 0];
    paramArrayOfint2[paramInt2 + 1] = paramArrayOfint1[paramInt1 + 1];
    paramArrayOfint2[paramInt2 + 2] = paramArrayOfint1[paramInt1 + 2];
    paramArrayOfint2[paramInt2 + 3] = paramArrayOfint1[paramInt1 + 3];
    paramArrayOfint2[paramInt2 + 4] = paramArrayOfint1[paramInt1 + 4];
    paramArrayOfint2[paramInt2 + 5] = paramArrayOfint1[paramInt1 + 5];
    paramArrayOfint2[paramInt2 + 6] = paramArrayOfint1[paramInt1 + 6];
    paramArrayOfint2[paramInt2 + 7] = paramArrayOfint1[paramInt1 + 7];
  }
  
  public static void copy64(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong1[0];
    paramArrayOflong2[1] = paramArrayOflong1[1];
    paramArrayOflong2[2] = paramArrayOflong1[2];
    paramArrayOflong2[3] = paramArrayOflong1[3];
  }
  
  public static void copy64(long[] paramArrayOflong1, int paramInt1, long[] paramArrayOflong2, int paramInt2) {
    paramArrayOflong2[paramInt2 + 0] = paramArrayOflong1[paramInt1 + 0];
    paramArrayOflong2[paramInt2 + 1] = paramArrayOflong1[paramInt1 + 1];
    paramArrayOflong2[paramInt2 + 2] = paramArrayOflong1[paramInt1 + 2];
    paramArrayOflong2[paramInt2 + 3] = paramArrayOflong1[paramInt1 + 3];
  }
  
  public static int[] create() {
    return new int[8];
  }
  
  public static long[] create64() {
    return new long[4];
  }
  
  public static int[] createExt() {
    return new int[16];
  }
  
  public static long[] createExt64() {
    return new long[8];
  }
  
  public static boolean diff(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2, int[] paramArrayOfint3, int paramInt3) {
    boolean bool = gte(paramArrayOfint1, paramInt1, paramArrayOfint2, paramInt2);
    if (bool) {
      sub(paramArrayOfint1, paramInt1, paramArrayOfint2, paramInt2, paramArrayOfint3, paramInt3);
    } else {
      sub(paramArrayOfint2, paramInt2, paramArrayOfint1, paramInt1, paramArrayOfint3, paramInt3);
    } 
    return bool;
  }
  
  public static boolean eq(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    for (byte b = 7; b >= 0; b--) {
      if (paramArrayOfint1[b] != paramArrayOfint2[b])
        return false; 
    } 
    return true;
  }
  
  public static boolean eq64(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    for (byte b = 3; b >= 0; b--) {
      if (paramArrayOflong1[b] != paramArrayOflong2[b])
        return false; 
    } 
    return true;
  }
  
  public static int[] fromBigInteger(BigInteger paramBigInteger) {
    if (paramBigInteger.signum() < 0 || paramBigInteger.bitLength() > 256)
      throw new IllegalArgumentException(); 
    int[] arrayOfInt = create();
    for (byte b = 0; b < 8; b++) {
      arrayOfInt[b] = paramBigInteger.intValue();
      paramBigInteger = paramBigInteger.shiftRight(32);
    } 
    return arrayOfInt;
  }
  
  public static long[] fromBigInteger64(BigInteger paramBigInteger) {
    if (paramBigInteger.signum() < 0 || paramBigInteger.bitLength() > 256)
      throw new IllegalArgumentException(); 
    long[] arrayOfLong = create64();
    for (byte b = 0; b < 4; b++) {
      arrayOfLong[b] = paramBigInteger.longValue();
      paramBigInteger = paramBigInteger.shiftRight(64);
    } 
    return arrayOfLong;
  }
  
  public static int getBit(int[] paramArrayOfint, int paramInt) {
    if (paramInt == 0)
      return paramArrayOfint[0] & 0x1; 
    if ((paramInt & 0xFF) != paramInt)
      return 0; 
    int i = paramInt >>> 5;
    int j = paramInt & 0x1F;
    return paramArrayOfint[i] >>> j & 0x1;
  }
  
  public static boolean gte(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    for (byte b = 7; b >= 0; b--) {
      int i = paramArrayOfint1[b] ^ Integer.MIN_VALUE;
      int j = paramArrayOfint2[b] ^ Integer.MIN_VALUE;
      if (i < j)
        return false; 
      if (i > j)
        return true; 
    } 
    return true;
  }
  
  public static boolean gte(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    for (byte b = 7; b >= 0; b--) {
      int i = paramArrayOfint1[paramInt1 + b] ^ Integer.MIN_VALUE;
      int j = paramArrayOfint2[paramInt2 + b] ^ Integer.MIN_VALUE;
      if (i < j)
        return false; 
      if (i > j)
        return true; 
    } 
    return true;
  }
  
  public static boolean isOne(int[] paramArrayOfint) {
    if (paramArrayOfint[0] != 1)
      return false; 
    for (byte b = 1; b < 8; b++) {
      if (paramArrayOfint[b] != 0)
        return false; 
    } 
    return true;
  }
  
  public static boolean isOne64(long[] paramArrayOflong) {
    if (paramArrayOflong[0] != 1L)
      return false; 
    for (byte b = 1; b < 4; b++) {
      if (paramArrayOflong[b] != 0L)
        return false; 
    } 
    return true;
  }
  
  public static boolean isZero(int[] paramArrayOfint) {
    for (byte b = 0; b < 8; b++) {
      if (paramArrayOfint[b] != 0)
        return false; 
    } 
    return true;
  }
  
  public static boolean isZero64(long[] paramArrayOflong) {
    for (byte b = 0; b < 4; b++) {
      if (paramArrayOflong[b] != 0L)
        return false; 
    } 
    return true;
  }
  
  public static void mul(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    long l1 = paramArrayOfint2[0] & 0xFFFFFFFFL;
    long l2 = paramArrayOfint2[1] & 0xFFFFFFFFL;
    long l3 = paramArrayOfint2[2] & 0xFFFFFFFFL;
    long l4 = paramArrayOfint2[3] & 0xFFFFFFFFL;
    long l5 = paramArrayOfint2[4] & 0xFFFFFFFFL;
    long l6 = paramArrayOfint2[5] & 0xFFFFFFFFL;
    long l7 = paramArrayOfint2[6] & 0xFFFFFFFFL;
    long l8 = paramArrayOfint2[7] & 0xFFFFFFFFL;
    long l9 = 0L, l10 = paramArrayOfint1[0] & 0xFFFFFFFFL;
    l9 += l10 * l1;
    paramArrayOfint3[0] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l2;
    paramArrayOfint3[1] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l3;
    paramArrayOfint3[2] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l4;
    paramArrayOfint3[3] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l5;
    paramArrayOfint3[4] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l6;
    paramArrayOfint3[5] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l7;
    paramArrayOfint3[6] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l8;
    paramArrayOfint3[7] = (int)l9;
    l9 >>>= 32L;
    paramArrayOfint3[8] = (int)l9;
    for (byte b = 1; b < 8; b++) {
      long l11 = 0L, l12 = paramArrayOfint1[b] & 0xFFFFFFFFL;
      l11 += l12 * l1 + (paramArrayOfint3[b + 0] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 0] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l2 + (paramArrayOfint3[b + 1] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 1] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l3 + (paramArrayOfint3[b + 2] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 2] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l4 + (paramArrayOfint3[b + 3] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 3] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l5 + (paramArrayOfint3[b + 4] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 4] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l6 + (paramArrayOfint3[b + 5] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 5] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l7 + (paramArrayOfint3[b + 6] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 6] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l8 + (paramArrayOfint3[b + 7] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 7] = (int)l11;
      l11 >>>= 32L;
      paramArrayOfint3[b + 8] = (int)l11;
    } 
  }
  
  public static void mul(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2, int[] paramArrayOfint3, int paramInt3) {
    long l1 = paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL;
    long l2 = paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL;
    long l3 = paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL;
    long l4 = paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL;
    long l5 = paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL;
    long l6 = paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL;
    long l7 = paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL;
    long l8 = paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL;
    long l9 = 0L, l10 = paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL;
    l9 += l10 * l1;
    paramArrayOfint3[paramInt3 + 0] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l2;
    paramArrayOfint3[paramInt3 + 1] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l3;
    paramArrayOfint3[paramInt3 + 2] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l4;
    paramArrayOfint3[paramInt3 + 3] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l5;
    paramArrayOfint3[paramInt3 + 4] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l6;
    paramArrayOfint3[paramInt3 + 5] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l7;
    paramArrayOfint3[paramInt3 + 6] = (int)l9;
    l9 >>>= 32L;
    l9 += l10 * l8;
    paramArrayOfint3[paramInt3 + 7] = (int)l9;
    l9 >>>= 32L;
    paramArrayOfint3[paramInt3 + 8] = (int)l9;
    for (byte b = 1; b < 8; b++) {
      paramInt3++;
      long l11 = 0L, l12 = paramArrayOfint1[paramInt1 + b] & 0xFFFFFFFFL;
      l11 += l12 * l1 + (paramArrayOfint3[paramInt3 + 0] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 0] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l2 + (paramArrayOfint3[paramInt3 + 1] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 1] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l3 + (paramArrayOfint3[paramInt3 + 2] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 2] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l4 + (paramArrayOfint3[paramInt3 + 3] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 3] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l5 + (paramArrayOfint3[paramInt3 + 4] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 4] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l6 + (paramArrayOfint3[paramInt3 + 5] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 5] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l7 + (paramArrayOfint3[paramInt3 + 6] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 6] = (int)l11;
      l11 >>>= 32L;
      l11 += l12 * l8 + (paramArrayOfint3[paramInt3 + 7] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 7] = (int)l11;
      l11 >>>= 32L;
      paramArrayOfint3[paramInt3 + 8] = (int)l11;
    } 
  }
  
  public static int mulAddTo(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    long l1 = paramArrayOfint2[0] & 0xFFFFFFFFL;
    long l2 = paramArrayOfint2[1] & 0xFFFFFFFFL;
    long l3 = paramArrayOfint2[2] & 0xFFFFFFFFL;
    long l4 = paramArrayOfint2[3] & 0xFFFFFFFFL;
    long l5 = paramArrayOfint2[4] & 0xFFFFFFFFL;
    long l6 = paramArrayOfint2[5] & 0xFFFFFFFFL;
    long l7 = paramArrayOfint2[6] & 0xFFFFFFFFL;
    long l8 = paramArrayOfint2[7] & 0xFFFFFFFFL;
    long l9 = 0L;
    for (byte b = 0; b < 8; b++) {
      long l10 = 0L, l11 = paramArrayOfint1[b] & 0xFFFFFFFFL;
      l10 += l11 * l1 + (paramArrayOfint3[b + 0] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 0] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l2 + (paramArrayOfint3[b + 1] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 1] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l3 + (paramArrayOfint3[b + 2] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 2] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l4 + (paramArrayOfint3[b + 3] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 3] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l5 + (paramArrayOfint3[b + 4] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 4] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l6 + (paramArrayOfint3[b + 5] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 5] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l7 + (paramArrayOfint3[b + 6] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 6] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l8 + (paramArrayOfint3[b + 7] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 7] = (int)l10;
      l10 >>>= 32L;
      l9 += l10 + (paramArrayOfint3[b + 8] & 0xFFFFFFFFL);
      paramArrayOfint3[b + 8] = (int)l9;
      l9 >>>= 32L;
    } 
    return (int)l9;
  }
  
  public static int mulAddTo(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2, int[] paramArrayOfint3, int paramInt3) {
    long l1 = paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL;
    long l2 = paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL;
    long l3 = paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL;
    long l4 = paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL;
    long l5 = paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL;
    long l6 = paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL;
    long l7 = paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL;
    long l8 = paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL;
    long l9 = 0L;
    for (byte b = 0; b < 8; b++) {
      long l10 = 0L, l11 = paramArrayOfint1[paramInt1 + b] & 0xFFFFFFFFL;
      l10 += l11 * l1 + (paramArrayOfint3[paramInt3 + 0] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 0] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l2 + (paramArrayOfint3[paramInt3 + 1] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 1] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l3 + (paramArrayOfint3[paramInt3 + 2] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 2] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l4 + (paramArrayOfint3[paramInt3 + 3] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 3] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l5 + (paramArrayOfint3[paramInt3 + 4] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 4] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l6 + (paramArrayOfint3[paramInt3 + 5] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 5] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l7 + (paramArrayOfint3[paramInt3 + 6] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 6] = (int)l10;
      l10 >>>= 32L;
      l10 += l11 * l8 + (paramArrayOfint3[paramInt3 + 7] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 7] = (int)l10;
      l10 >>>= 32L;
      l9 += l10 + (paramArrayOfint3[paramInt3 + 8] & 0xFFFFFFFFL);
      paramArrayOfint3[paramInt3 + 8] = (int)l9;
      l9 >>>= 32L;
      paramInt3++;
    } 
    return (int)l9;
  }
  
  public static long mul33Add(int paramInt1, int[] paramArrayOfint1, int paramInt2, int[] paramArrayOfint2, int paramInt3, int[] paramArrayOfint3, int paramInt4) {
    long l1 = 0L, l2 = paramInt1 & 0xFFFFFFFFL;
    long l3 = paramArrayOfint1[paramInt2 + 0] & 0xFFFFFFFFL;
    l1 += l2 * l3 + (paramArrayOfint2[paramInt3 + 0] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 0] = (int)l1;
    l1 >>>= 32L;
    long l4 = paramArrayOfint1[paramInt2 + 1] & 0xFFFFFFFFL;
    l1 += l2 * l4 + l3 + (paramArrayOfint2[paramInt3 + 1] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 1] = (int)l1;
    l1 >>>= 32L;
    long l5 = paramArrayOfint1[paramInt2 + 2] & 0xFFFFFFFFL;
    l1 += l2 * l5 + l4 + (paramArrayOfint2[paramInt3 + 2] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 2] = (int)l1;
    l1 >>>= 32L;
    long l6 = paramArrayOfint1[paramInt2 + 3] & 0xFFFFFFFFL;
    l1 += l2 * l6 + l5 + (paramArrayOfint2[paramInt3 + 3] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 3] = (int)l1;
    l1 >>>= 32L;
    long l7 = paramArrayOfint1[paramInt2 + 4] & 0xFFFFFFFFL;
    l1 += l2 * l7 + l6 + (paramArrayOfint2[paramInt3 + 4] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 4] = (int)l1;
    l1 >>>= 32L;
    long l8 = paramArrayOfint1[paramInt2 + 5] & 0xFFFFFFFFL;
    l1 += l2 * l8 + l7 + (paramArrayOfint2[paramInt3 + 5] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 5] = (int)l1;
    l1 >>>= 32L;
    long l9 = paramArrayOfint1[paramInt2 + 6] & 0xFFFFFFFFL;
    l1 += l2 * l9 + l8 + (paramArrayOfint2[paramInt3 + 6] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 6] = (int)l1;
    l1 >>>= 32L;
    long l10 = paramArrayOfint1[paramInt2 + 7] & 0xFFFFFFFFL;
    l1 += l2 * l10 + l9 + (paramArrayOfint2[paramInt3 + 7] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt4 + 7] = (int)l1;
    l1 >>>= 32L;
    l1 += l10;
    return l1;
  }
  
  public static int mulByWord(int paramInt, int[] paramArrayOfint) {
    long l1 = 0L, l2 = paramInt & 0xFFFFFFFFL;
    l1 += l2 * (paramArrayOfint[0] & 0xFFFFFFFFL);
    paramArrayOfint[0] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint[1] & 0xFFFFFFFFL);
    paramArrayOfint[1] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint[2] & 0xFFFFFFFFL);
    paramArrayOfint[2] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint[3] & 0xFFFFFFFFL);
    paramArrayOfint[3] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint[4] & 0xFFFFFFFFL);
    paramArrayOfint[4] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint[5] & 0xFFFFFFFFL);
    paramArrayOfint[5] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint[6] & 0xFFFFFFFFL);
    paramArrayOfint[6] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint[7] & 0xFFFFFFFFL);
    paramArrayOfint[7] = (int)l1;
    l1 >>>= 32L;
    return (int)l1;
  }
  
  public static int mulByWordAddTo(int paramInt, int[] paramArrayOfint1, int[] paramArrayOfint2) {
    long l1 = 0L, l2 = paramInt & 0xFFFFFFFFL;
    l1 += l2 * (paramArrayOfint2[0] & 0xFFFFFFFFL) + (paramArrayOfint1[0] & 0xFFFFFFFFL);
    paramArrayOfint2[0] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint2[1] & 0xFFFFFFFFL) + (paramArrayOfint1[1] & 0xFFFFFFFFL);
    paramArrayOfint2[1] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint2[2] & 0xFFFFFFFFL) + (paramArrayOfint1[2] & 0xFFFFFFFFL);
    paramArrayOfint2[2] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint2[3] & 0xFFFFFFFFL) + (paramArrayOfint1[3] & 0xFFFFFFFFL);
    paramArrayOfint2[3] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint2[4] & 0xFFFFFFFFL) + (paramArrayOfint1[4] & 0xFFFFFFFFL);
    paramArrayOfint2[4] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint2[5] & 0xFFFFFFFFL) + (paramArrayOfint1[5] & 0xFFFFFFFFL);
    paramArrayOfint2[5] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint2[6] & 0xFFFFFFFFL) + (paramArrayOfint1[6] & 0xFFFFFFFFL);
    paramArrayOfint2[6] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint2[7] & 0xFFFFFFFFL) + (paramArrayOfint1[7] & 0xFFFFFFFFL);
    paramArrayOfint2[7] = (int)l1;
    l1 >>>= 32L;
    return (int)l1;
  }
  
  public static int mulWordAddTo(int paramInt1, int[] paramArrayOfint1, int paramInt2, int[] paramArrayOfint2, int paramInt3) {
    long l1 = 0L, l2 = paramInt1 & 0xFFFFFFFFL;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 0] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 0] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 0] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 1] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 1] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 1] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 2] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 2] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 2] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 3] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 3] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 3] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 4] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 4] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 4] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 5] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 5] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 5] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 6] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 6] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 6] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramArrayOfint1[paramInt2 + 7] & 0xFFFFFFFFL) + (paramArrayOfint2[paramInt3 + 7] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt3 + 7] = (int)l1;
    l1 >>>= 32L;
    return (int)l1;
  }
  
  public static int mul33DWordAdd(int paramInt1, long paramLong, int[] paramArrayOfint, int paramInt2) {
    long l1 = 0L, l2 = paramInt1 & 0xFFFFFFFFL;
    long l3 = paramLong & 0xFFFFFFFFL;
    l1 += l2 * l3 + (paramArrayOfint[paramInt2 + 0] & 0xFFFFFFFFL);
    paramArrayOfint[paramInt2 + 0] = (int)l1;
    l1 >>>= 32L;
    long l4 = paramLong >>> 32L;
    l1 += l2 * l4 + l3 + (paramArrayOfint[paramInt2 + 1] & 0xFFFFFFFFL);
    paramArrayOfint[paramInt2 + 1] = (int)l1;
    l1 >>>= 32L;
    l1 += l4 + (paramArrayOfint[paramInt2 + 2] & 0xFFFFFFFFL);
    paramArrayOfint[paramInt2 + 2] = (int)l1;
    l1 >>>= 32L;
    l1 += paramArrayOfint[paramInt2 + 3] & 0xFFFFFFFFL;
    paramArrayOfint[paramInt2 + 3] = (int)l1;
    l1 >>>= 32L;
    return (l1 == 0L) ? 0 : Nat.incAt(8, paramArrayOfint, paramInt2, 4);
  }
  
  public static int mul33WordAdd(int paramInt1, int paramInt2, int[] paramArrayOfint, int paramInt3) {
    long l1 = 0L, l2 = paramInt1 & 0xFFFFFFFFL, l3 = paramInt2 & 0xFFFFFFFFL;
    l1 += l3 * l2 + (paramArrayOfint[paramInt3 + 0] & 0xFFFFFFFFL);
    paramArrayOfint[paramInt3 + 0] = (int)l1;
    l1 >>>= 32L;
    l1 += l3 + (paramArrayOfint[paramInt3 + 1] & 0xFFFFFFFFL);
    paramArrayOfint[paramInt3 + 1] = (int)l1;
    l1 >>>= 32L;
    l1 += paramArrayOfint[paramInt3 + 2] & 0xFFFFFFFFL;
    paramArrayOfint[paramInt3 + 2] = (int)l1;
    l1 >>>= 32L;
    return (l1 == 0L) ? 0 : Nat.incAt(8, paramArrayOfint, paramInt3, 3);
  }
  
  public static int mulWordDwordAdd(int paramInt1, long paramLong, int[] paramArrayOfint, int paramInt2) {
    long l1 = 0L, l2 = paramInt1 & 0xFFFFFFFFL;
    l1 += l2 * (paramLong & 0xFFFFFFFFL) + (paramArrayOfint[paramInt2 + 0] & 0xFFFFFFFFL);
    paramArrayOfint[paramInt2 + 0] = (int)l1;
    l1 >>>= 32L;
    l1 += l2 * (paramLong >>> 32L) + (paramArrayOfint[paramInt2 + 1] & 0xFFFFFFFFL);
    paramArrayOfint[paramInt2 + 1] = (int)l1;
    l1 >>>= 32L;
    l1 += paramArrayOfint[paramInt2 + 2] & 0xFFFFFFFFL;
    paramArrayOfint[paramInt2 + 2] = (int)l1;
    l1 >>>= 32L;
    return (l1 == 0L) ? 0 : Nat.incAt(8, paramArrayOfint, paramInt2, 3);
  }
  
  public static int mulWord(int paramInt1, int[] paramArrayOfint1, int[] paramArrayOfint2, int paramInt2) {
    long l1 = 0L, l2 = paramInt1 & 0xFFFFFFFFL;
    byte b = 0;
    while (true) {
      l1 += l2 * (paramArrayOfint1[b] & 0xFFFFFFFFL);
      paramArrayOfint2[paramInt2 + b] = (int)l1;
      l1 >>>= 32L;
      if (++b >= 8)
        return (int)l1; 
    } 
  }
  
  public static void square(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    long l1 = paramArrayOfint1[0] & 0xFFFFFFFFL;
    int i = 0;
    byte b1 = 7, b2 = 16;
    do {
      long l23 = paramArrayOfint1[b1--] & 0xFFFFFFFFL;
      long l24 = l23 * l23;
      paramArrayOfint2[--b2] = i << 31 | (int)(l24 >>> 33L);
      paramArrayOfint2[--b2] = (int)(l24 >>> 1L);
      i = (int)l24;
    } while (b1 > 0);
    long l4 = l1 * l1;
    long l2 = (i << 31) & 0xFFFFFFFFL | l4 >>> 33L;
    paramArrayOfint2[0] = (int)l4;
    i = (int)(l4 >>> 32L) & 0x1;
    long l3 = paramArrayOfint1[1] & 0xFFFFFFFFL;
    l4 = paramArrayOfint2[2] & 0xFFFFFFFFL;
    l2 += l3 * l1;
    int j = (int)l2;
    paramArrayOfint2[1] = j << 1 | i;
    i = j >>> 31;
    l4 += l2 >>> 32L;
    long l5 = paramArrayOfint1[2] & 0xFFFFFFFFL;
    long l6 = paramArrayOfint2[3] & 0xFFFFFFFFL;
    long l7 = paramArrayOfint2[4] & 0xFFFFFFFFL;
    l4 += l5 * l1;
    j = (int)l4;
    paramArrayOfint2[2] = j << 1 | i;
    i = j >>> 31;
    l6 += (l4 >>> 32L) + l5 * l3;
    l7 += l6 >>> 32L;
    l6 &= 0xFFFFFFFFL;
    long l8 = paramArrayOfint1[3] & 0xFFFFFFFFL;
    long l9 = (paramArrayOfint2[5] & 0xFFFFFFFFL) + (l7 >>> 32L);
    l7 &= 0xFFFFFFFFL;
    long l10 = (paramArrayOfint2[6] & 0xFFFFFFFFL) + (l9 >>> 32L);
    l9 &= 0xFFFFFFFFL;
    l6 += l8 * l1;
    j = (int)l6;
    paramArrayOfint2[3] = j << 1 | i;
    i = j >>> 31;
    l7 += (l6 >>> 32L) + l8 * l3;
    l9 += (l7 >>> 32L) + l8 * l5;
    l7 &= 0xFFFFFFFFL;
    l10 += l9 >>> 32L;
    l9 &= 0xFFFFFFFFL;
    long l11 = paramArrayOfint1[4] & 0xFFFFFFFFL;
    long l12 = (paramArrayOfint2[7] & 0xFFFFFFFFL) + (l10 >>> 32L);
    l10 &= 0xFFFFFFFFL;
    long l13 = (paramArrayOfint2[8] & 0xFFFFFFFFL) + (l12 >>> 32L);
    l12 &= 0xFFFFFFFFL;
    l7 += l11 * l1;
    j = (int)l7;
    paramArrayOfint2[4] = j << 1 | i;
    i = j >>> 31;
    l9 += (l7 >>> 32L) + l11 * l3;
    l10 += (l9 >>> 32L) + l11 * l5;
    l9 &= 0xFFFFFFFFL;
    l12 += (l10 >>> 32L) + l11 * l8;
    l10 &= 0xFFFFFFFFL;
    l13 += l12 >>> 32L;
    l12 &= 0xFFFFFFFFL;
    long l14 = paramArrayOfint1[5] & 0xFFFFFFFFL;
    long l15 = (paramArrayOfint2[9] & 0xFFFFFFFFL) + (l13 >>> 32L);
    l13 &= 0xFFFFFFFFL;
    long l16 = (paramArrayOfint2[10] & 0xFFFFFFFFL) + (l15 >>> 32L);
    l15 &= 0xFFFFFFFFL;
    l9 += l14 * l1;
    j = (int)l9;
    paramArrayOfint2[5] = j << 1 | i;
    i = j >>> 31;
    l10 += (l9 >>> 32L) + l14 * l3;
    l12 += (l10 >>> 32L) + l14 * l5;
    l10 &= 0xFFFFFFFFL;
    l13 += (l12 >>> 32L) + l14 * l8;
    l12 &= 0xFFFFFFFFL;
    l15 += (l13 >>> 32L) + l14 * l11;
    l13 &= 0xFFFFFFFFL;
    l16 += l15 >>> 32L;
    l15 &= 0xFFFFFFFFL;
    long l17 = paramArrayOfint1[6] & 0xFFFFFFFFL;
    long l18 = (paramArrayOfint2[11] & 0xFFFFFFFFL) + (l16 >>> 32L);
    l16 &= 0xFFFFFFFFL;
    long l19 = (paramArrayOfint2[12] & 0xFFFFFFFFL) + (l18 >>> 32L);
    l18 &= 0xFFFFFFFFL;
    l10 += l17 * l1;
    j = (int)l10;
    paramArrayOfint2[6] = j << 1 | i;
    i = j >>> 31;
    l12 += (l10 >>> 32L) + l17 * l3;
    l13 += (l12 >>> 32L) + l17 * l5;
    l12 &= 0xFFFFFFFFL;
    l15 += (l13 >>> 32L) + l17 * l8;
    l13 &= 0xFFFFFFFFL;
    l16 += (l15 >>> 32L) + l17 * l11;
    l15 &= 0xFFFFFFFFL;
    l18 += (l16 >>> 32L) + l17 * l14;
    l16 &= 0xFFFFFFFFL;
    l19 += l18 >>> 32L;
    l18 &= 0xFFFFFFFFL;
    long l20 = paramArrayOfint1[7] & 0xFFFFFFFFL;
    long l21 = (paramArrayOfint2[13] & 0xFFFFFFFFL) + (l19 >>> 32L);
    l19 &= 0xFFFFFFFFL;
    long l22 = (paramArrayOfint2[14] & 0xFFFFFFFFL) + (l21 >>> 32L);
    l21 &= 0xFFFFFFFFL;
    l12 += l20 * l1;
    j = (int)l12;
    paramArrayOfint2[7] = j << 1 | i;
    i = j >>> 31;
    l13 += (l12 >>> 32L) + l20 * l3;
    l15 += (l13 >>> 32L) + l20 * l5;
    l16 += (l15 >>> 32L) + l20 * l8;
    l18 += (l16 >>> 32L) + l20 * l11;
    l19 += (l18 >>> 32L) + l20 * l14;
    l21 += (l19 >>> 32L) + l20 * l17;
    l22 += l21 >>> 32L;
    j = (int)l13;
    paramArrayOfint2[8] = j << 1 | i;
    i = j >>> 31;
    j = (int)l15;
    paramArrayOfint2[9] = j << 1 | i;
    i = j >>> 31;
    j = (int)l16;
    paramArrayOfint2[10] = j << 1 | i;
    i = j >>> 31;
    j = (int)l18;
    paramArrayOfint2[11] = j << 1 | i;
    i = j >>> 31;
    j = (int)l19;
    paramArrayOfint2[12] = j << 1 | i;
    i = j >>> 31;
    j = (int)l21;
    paramArrayOfint2[13] = j << 1 | i;
    i = j >>> 31;
    j = (int)l22;
    paramArrayOfint2[14] = j << 1 | i;
    i = j >>> 31;
    j = paramArrayOfint2[15] + (int)(l22 >>> 32L);
    paramArrayOfint2[15] = j << 1 | i;
  }
  
  public static void square(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    long l1 = paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL;
    int i = 0;
    byte b1 = 7, b2 = 16;
    do {
      long l23 = paramArrayOfint1[paramInt1 + b1--] & 0xFFFFFFFFL;
      long l24 = l23 * l23;
      paramArrayOfint2[paramInt2 + --b2] = i << 31 | (int)(l24 >>> 33L);
      paramArrayOfint2[paramInt2 + --b2] = (int)(l24 >>> 1L);
      i = (int)l24;
    } while (b1 > 0);
    long l4 = l1 * l1;
    long l2 = (i << 31) & 0xFFFFFFFFL | l4 >>> 33L;
    paramArrayOfint2[paramInt2 + 0] = (int)l4;
    i = (int)(l4 >>> 32L) & 0x1;
    long l3 = paramArrayOfint1[paramInt1 + 1] & 0xFFFFFFFFL;
    l4 = paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL;
    l2 += l3 * l1;
    int j = (int)l2;
    paramArrayOfint2[paramInt2 + 1] = j << 1 | i;
    i = j >>> 31;
    l4 += l2 >>> 32L;
    long l5 = paramArrayOfint1[paramInt1 + 2] & 0xFFFFFFFFL;
    long l6 = paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL;
    long l7 = paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL;
    l4 += l5 * l1;
    j = (int)l4;
    paramArrayOfint2[paramInt2 + 2] = j << 1 | i;
    i = j >>> 31;
    l6 += (l4 >>> 32L) + l5 * l3;
    l7 += l6 >>> 32L;
    l6 &= 0xFFFFFFFFL;
    long l8 = paramArrayOfint1[paramInt1 + 3] & 0xFFFFFFFFL;
    long l9 = (paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL) + (l7 >>> 32L);
    l7 &= 0xFFFFFFFFL;
    long l10 = (paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL) + (l9 >>> 32L);
    l9 &= 0xFFFFFFFFL;
    l6 += l8 * l1;
    j = (int)l6;
    paramArrayOfint2[paramInt2 + 3] = j << 1 | i;
    i = j >>> 31;
    l7 += (l6 >>> 32L) + l8 * l3;
    l9 += (l7 >>> 32L) + l8 * l5;
    l7 &= 0xFFFFFFFFL;
    l10 += l9 >>> 32L;
    l9 &= 0xFFFFFFFFL;
    long l11 = paramArrayOfint1[paramInt1 + 4] & 0xFFFFFFFFL;
    long l12 = (paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL) + (l10 >>> 32L);
    l10 &= 0xFFFFFFFFL;
    long l13 = (paramArrayOfint2[paramInt2 + 8] & 0xFFFFFFFFL) + (l12 >>> 32L);
    l12 &= 0xFFFFFFFFL;
    l7 += l11 * l1;
    j = (int)l7;
    paramArrayOfint2[paramInt2 + 4] = j << 1 | i;
    i = j >>> 31;
    l9 += (l7 >>> 32L) + l11 * l3;
    l10 += (l9 >>> 32L) + l11 * l5;
    l9 &= 0xFFFFFFFFL;
    l12 += (l10 >>> 32L) + l11 * l8;
    l10 &= 0xFFFFFFFFL;
    l13 += l12 >>> 32L;
    l12 &= 0xFFFFFFFFL;
    long l14 = paramArrayOfint1[paramInt1 + 5] & 0xFFFFFFFFL;
    long l15 = (paramArrayOfint2[paramInt2 + 9] & 0xFFFFFFFFL) + (l13 >>> 32L);
    l13 &= 0xFFFFFFFFL;
    long l16 = (paramArrayOfint2[paramInt2 + 10] & 0xFFFFFFFFL) + (l15 >>> 32L);
    l15 &= 0xFFFFFFFFL;
    l9 += l14 * l1;
    j = (int)l9;
    paramArrayOfint2[paramInt2 + 5] = j << 1 | i;
    i = j >>> 31;
    l10 += (l9 >>> 32L) + l14 * l3;
    l12 += (l10 >>> 32L) + l14 * l5;
    l10 &= 0xFFFFFFFFL;
    l13 += (l12 >>> 32L) + l14 * l8;
    l12 &= 0xFFFFFFFFL;
    l15 += (l13 >>> 32L) + l14 * l11;
    l13 &= 0xFFFFFFFFL;
    l16 += l15 >>> 32L;
    l15 &= 0xFFFFFFFFL;
    long l17 = paramArrayOfint1[paramInt1 + 6] & 0xFFFFFFFFL;
    long l18 = (paramArrayOfint2[paramInt2 + 11] & 0xFFFFFFFFL) + (l16 >>> 32L);
    l16 &= 0xFFFFFFFFL;
    long l19 = (paramArrayOfint2[paramInt2 + 12] & 0xFFFFFFFFL) + (l18 >>> 32L);
    l18 &= 0xFFFFFFFFL;
    l10 += l17 * l1;
    j = (int)l10;
    paramArrayOfint2[paramInt2 + 6] = j << 1 | i;
    i = j >>> 31;
    l12 += (l10 >>> 32L) + l17 * l3;
    l13 += (l12 >>> 32L) + l17 * l5;
    l12 &= 0xFFFFFFFFL;
    l15 += (l13 >>> 32L) + l17 * l8;
    l13 &= 0xFFFFFFFFL;
    l16 += (l15 >>> 32L) + l17 * l11;
    l15 &= 0xFFFFFFFFL;
    l18 += (l16 >>> 32L) + l17 * l14;
    l16 &= 0xFFFFFFFFL;
    l19 += l18 >>> 32L;
    l18 &= 0xFFFFFFFFL;
    long l20 = paramArrayOfint1[paramInt1 + 7] & 0xFFFFFFFFL;
    long l21 = (paramArrayOfint2[paramInt2 + 13] & 0xFFFFFFFFL) + (l19 >>> 32L);
    l19 &= 0xFFFFFFFFL;
    long l22 = (paramArrayOfint2[paramInt2 + 14] & 0xFFFFFFFFL) + (l21 >>> 32L);
    l21 &= 0xFFFFFFFFL;
    l12 += l20 * l1;
    j = (int)l12;
    paramArrayOfint2[paramInt2 + 7] = j << 1 | i;
    i = j >>> 31;
    l13 += (l12 >>> 32L) + l20 * l3;
    l15 += (l13 >>> 32L) + l20 * l5;
    l16 += (l15 >>> 32L) + l20 * l8;
    l18 += (l16 >>> 32L) + l20 * l11;
    l19 += (l18 >>> 32L) + l20 * l14;
    l21 += (l19 >>> 32L) + l20 * l17;
    l22 += l21 >>> 32L;
    j = (int)l13;
    paramArrayOfint2[paramInt2 + 8] = j << 1 | i;
    i = j >>> 31;
    j = (int)l15;
    paramArrayOfint2[paramInt2 + 9] = j << 1 | i;
    i = j >>> 31;
    j = (int)l16;
    paramArrayOfint2[paramInt2 + 10] = j << 1 | i;
    i = j >>> 31;
    j = (int)l18;
    paramArrayOfint2[paramInt2 + 11] = j << 1 | i;
    i = j >>> 31;
    j = (int)l19;
    paramArrayOfint2[paramInt2 + 12] = j << 1 | i;
    i = j >>> 31;
    j = (int)l21;
    paramArrayOfint2[paramInt2 + 13] = j << 1 | i;
    i = j >>> 31;
    j = (int)l22;
    paramArrayOfint2[paramInt2 + 14] = j << 1 | i;
    i = j >>> 31;
    j = paramArrayOfint2[paramInt2 + 15] + (int)(l22 >>> 32L);
    paramArrayOfint2[paramInt2 + 15] = j << 1 | i;
  }
  
  public static int sub(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    long l = 0L;
    l += (paramArrayOfint1[0] & 0xFFFFFFFFL) - (paramArrayOfint2[0] & 0xFFFFFFFFL);
    paramArrayOfint3[0] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[1] & 0xFFFFFFFFL) - (paramArrayOfint2[1] & 0xFFFFFFFFL);
    paramArrayOfint3[1] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[2] & 0xFFFFFFFFL) - (paramArrayOfint2[2] & 0xFFFFFFFFL);
    paramArrayOfint3[2] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[3] & 0xFFFFFFFFL) - (paramArrayOfint2[3] & 0xFFFFFFFFL);
    paramArrayOfint3[3] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[4] & 0xFFFFFFFFL) - (paramArrayOfint2[4] & 0xFFFFFFFFL);
    paramArrayOfint3[4] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[5] & 0xFFFFFFFFL) - (paramArrayOfint2[5] & 0xFFFFFFFFL);
    paramArrayOfint3[5] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[6] & 0xFFFFFFFFL) - (paramArrayOfint2[6] & 0xFFFFFFFFL);
    paramArrayOfint3[6] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[7] & 0xFFFFFFFFL) - (paramArrayOfint2[7] & 0xFFFFFFFFL);
    paramArrayOfint3[7] = (int)l;
    l >>= 32L;
    return (int)l;
  }
  
  public static int sub(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2, int[] paramArrayOfint3, int paramInt3) {
    long l = 0L;
    l += (paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 0] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[paramInt1 + 1] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 1] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[paramInt1 + 2] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 2] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[paramInt1 + 3] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 3] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[paramInt1 + 4] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 4] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[paramInt1 + 5] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 5] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[paramInt1 + 6] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 6] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint1[paramInt1 + 7] & 0xFFFFFFFFL) - (paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL);
    paramArrayOfint3[paramInt3 + 7] = (int)l;
    l >>= 32L;
    return (int)l;
  }
  
  public static int subBothFrom(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    long l = 0L;
    l += (paramArrayOfint3[0] & 0xFFFFFFFFL) - (paramArrayOfint1[0] & 0xFFFFFFFFL) - (paramArrayOfint2[0] & 0xFFFFFFFFL);
    paramArrayOfint3[0] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint3[1] & 0xFFFFFFFFL) - (paramArrayOfint1[1] & 0xFFFFFFFFL) - (paramArrayOfint2[1] & 0xFFFFFFFFL);
    paramArrayOfint3[1] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint3[2] & 0xFFFFFFFFL) - (paramArrayOfint1[2] & 0xFFFFFFFFL) - (paramArrayOfint2[2] & 0xFFFFFFFFL);
    paramArrayOfint3[2] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint3[3] & 0xFFFFFFFFL) - (paramArrayOfint1[3] & 0xFFFFFFFFL) - (paramArrayOfint2[3] & 0xFFFFFFFFL);
    paramArrayOfint3[3] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint3[4] & 0xFFFFFFFFL) - (paramArrayOfint1[4] & 0xFFFFFFFFL) - (paramArrayOfint2[4] & 0xFFFFFFFFL);
    paramArrayOfint3[4] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint3[5] & 0xFFFFFFFFL) - (paramArrayOfint1[5] & 0xFFFFFFFFL) - (paramArrayOfint2[5] & 0xFFFFFFFFL);
    paramArrayOfint3[5] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint3[6] & 0xFFFFFFFFL) - (paramArrayOfint1[6] & 0xFFFFFFFFL) - (paramArrayOfint2[6] & 0xFFFFFFFFL);
    paramArrayOfint3[6] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint3[7] & 0xFFFFFFFFL) - (paramArrayOfint1[7] & 0xFFFFFFFFL) - (paramArrayOfint2[7] & 0xFFFFFFFFL);
    paramArrayOfint3[7] = (int)l;
    l >>= 32L;
    return (int)l;
  }
  
  public static int subFrom(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    long l = 0L;
    l += (paramArrayOfint2[0] & 0xFFFFFFFFL) - (paramArrayOfint1[0] & 0xFFFFFFFFL);
    paramArrayOfint2[0] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[1] & 0xFFFFFFFFL) - (paramArrayOfint1[1] & 0xFFFFFFFFL);
    paramArrayOfint2[1] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[2] & 0xFFFFFFFFL) - (paramArrayOfint1[2] & 0xFFFFFFFFL);
    paramArrayOfint2[2] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[3] & 0xFFFFFFFFL) - (paramArrayOfint1[3] & 0xFFFFFFFFL);
    paramArrayOfint2[3] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[4] & 0xFFFFFFFFL) - (paramArrayOfint1[4] & 0xFFFFFFFFL);
    paramArrayOfint2[4] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[5] & 0xFFFFFFFFL) - (paramArrayOfint1[5] & 0xFFFFFFFFL);
    paramArrayOfint2[5] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[6] & 0xFFFFFFFFL) - (paramArrayOfint1[6] & 0xFFFFFFFFL);
    paramArrayOfint2[6] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[7] & 0xFFFFFFFFL) - (paramArrayOfint1[7] & 0xFFFFFFFFL);
    paramArrayOfint2[7] = (int)l;
    l >>= 32L;
    return (int)l;
  }
  
  public static int subFrom(int[] paramArrayOfint1, int paramInt1, int[] paramArrayOfint2, int paramInt2) {
    long l = 0L;
    l += (paramArrayOfint2[paramInt2 + 0] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 0] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 0] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[paramInt2 + 1] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 1] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 1] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[paramInt2 + 2] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 2] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 2] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[paramInt2 + 3] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 3] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 3] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[paramInt2 + 4] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 4] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 4] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[paramInt2 + 5] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 5] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 5] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[paramInt2 + 6] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 6] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 6] = (int)l;
    l >>= 32L;
    l += (paramArrayOfint2[paramInt2 + 7] & 0xFFFFFFFFL) - (paramArrayOfint1[paramInt1 + 7] & 0xFFFFFFFFL);
    paramArrayOfint2[paramInt2 + 7] = (int)l;
    l >>= 32L;
    return (int)l;
  }
  
  public static BigInteger toBigInteger(int[] paramArrayOfint) {
    byte[] arrayOfByte = new byte[32];
    for (byte b = 0; b < 8; b++) {
      int i = paramArrayOfint[b];
      if (i != 0)
        Pack.intToBigEndian(i, arrayOfByte, 7 - b << 2); 
    } 
    return new BigInteger(1, arrayOfByte);
  }
  
  public static BigInteger toBigInteger64(long[] paramArrayOflong) {
    byte[] arrayOfByte = new byte[32];
    for (byte b = 0; b < 4; b++) {
      long l = paramArrayOflong[b];
      if (l != 0L)
        Pack.longToBigEndian(l, arrayOfByte, 3 - b << 3); 
    } 
    return new BigInteger(1, arrayOfByte);
  }
  
  public static void zero(int[] paramArrayOfint) {
    paramArrayOfint[0] = 0;
    paramArrayOfint[1] = 0;
    paramArrayOfint[2] = 0;
    paramArrayOfint[3] = 0;
    paramArrayOfint[4] = 0;
    paramArrayOfint[5] = 0;
    paramArrayOfint[6] = 0;
    paramArrayOfint[7] = 0;
  }
}
