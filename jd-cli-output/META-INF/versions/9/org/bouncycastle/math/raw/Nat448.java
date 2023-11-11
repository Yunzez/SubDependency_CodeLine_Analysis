package META-INF.versions.9.org.bouncycastle.math.raw;

import java.math.BigInteger;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat224;
import org.bouncycastle.util.Pack;

public abstract class Nat448 {
  public static void copy64(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    paramArrayOflong2[0] = paramArrayOflong1[0];
    paramArrayOflong2[1] = paramArrayOflong1[1];
    paramArrayOflong2[2] = paramArrayOflong1[2];
    paramArrayOflong2[3] = paramArrayOflong1[3];
    paramArrayOflong2[4] = paramArrayOflong1[4];
    paramArrayOflong2[5] = paramArrayOflong1[5];
    paramArrayOflong2[6] = paramArrayOflong1[6];
  }
  
  public static void copy64(long[] paramArrayOflong1, int paramInt1, long[] paramArrayOflong2, int paramInt2) {
    paramArrayOflong2[paramInt2 + 0] = paramArrayOflong1[paramInt1 + 0];
    paramArrayOflong2[paramInt2 + 1] = paramArrayOflong1[paramInt1 + 1];
    paramArrayOflong2[paramInt2 + 2] = paramArrayOflong1[paramInt1 + 2];
    paramArrayOflong2[paramInt2 + 3] = paramArrayOflong1[paramInt1 + 3];
    paramArrayOflong2[paramInt2 + 4] = paramArrayOflong1[paramInt1 + 4];
    paramArrayOflong2[paramInt2 + 5] = paramArrayOflong1[paramInt1 + 5];
    paramArrayOflong2[paramInt2 + 6] = paramArrayOflong1[paramInt1 + 6];
  }
  
  public static long[] create64() {
    return new long[7];
  }
  
  public static long[] createExt64() {
    return new long[14];
  }
  
  public static boolean eq64(long[] paramArrayOflong1, long[] paramArrayOflong2) {
    for (byte b = 6; b >= 0; b--) {
      if (paramArrayOflong1[b] != paramArrayOflong2[b])
        return false; 
    } 
    return true;
  }
  
  public static long[] fromBigInteger64(BigInteger paramBigInteger) {
    if (paramBigInteger.signum() < 0 || paramBigInteger.bitLength() > 448)
      throw new IllegalArgumentException(); 
    long[] arrayOfLong = create64();
    for (byte b = 0; b < 7; b++) {
      arrayOfLong[b] = paramBigInteger.longValue();
      paramBigInteger = paramBigInteger.shiftRight(64);
    } 
    return arrayOfLong;
  }
  
  public static boolean isOne64(long[] paramArrayOflong) {
    if (paramArrayOflong[0] != 1L)
      return false; 
    for (byte b = 1; b < 7; b++) {
      if (paramArrayOflong[b] != 0L)
        return false; 
    } 
    return true;
  }
  
  public static boolean isZero64(long[] paramArrayOflong) {
    for (byte b = 0; b < 7; b++) {
      if (paramArrayOflong[b] != 0L)
        return false; 
    } 
    return true;
  }
  
  public static void mul(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    Nat224.mul(paramArrayOfint1, paramArrayOfint2, paramArrayOfint3);
    Nat224.mul(paramArrayOfint1, 7, paramArrayOfint2, 7, paramArrayOfint3, 14);
    int i = Nat224.addToEachOther(paramArrayOfint3, 7, paramArrayOfint3, 14);
    int j = i + Nat224.addTo(paramArrayOfint3, 0, paramArrayOfint3, 7, 0);
    i += Nat224.addTo(paramArrayOfint3, 21, paramArrayOfint3, 14, j);
    int[] arrayOfInt1 = Nat224.create(), arrayOfInt2 = Nat224.create();
    boolean bool = (Nat224.diff(paramArrayOfint1, 7, paramArrayOfint1, 0, arrayOfInt1, 0) != Nat224.diff(paramArrayOfint2, 7, paramArrayOfint2, 0, arrayOfInt2, 0)) ? true : false;
    int[] arrayOfInt3 = Nat224.createExt();
    Nat224.mul(arrayOfInt1, arrayOfInt2, arrayOfInt3);
    i += bool ? Nat.addTo(14, arrayOfInt3, 0, paramArrayOfint3, 7) : Nat.subFrom(14, arrayOfInt3, 0, paramArrayOfint3, 7);
    Nat.addWordAt(28, i, paramArrayOfint3, 21);
  }
  
  public static void square(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    Nat224.square(paramArrayOfint1, paramArrayOfint2);
    Nat224.square(paramArrayOfint1, 7, paramArrayOfint2, 14);
    int i = Nat224.addToEachOther(paramArrayOfint2, 7, paramArrayOfint2, 14);
    int j = i + Nat224.addTo(paramArrayOfint2, 0, paramArrayOfint2, 7, 0);
    i += Nat224.addTo(paramArrayOfint2, 21, paramArrayOfint2, 14, j);
    int[] arrayOfInt1 = Nat224.create();
    Nat224.diff(paramArrayOfint1, 7, paramArrayOfint1, 0, arrayOfInt1, 0);
    int[] arrayOfInt2 = Nat224.createExt();
    Nat224.square(arrayOfInt1, arrayOfInt2);
    i += Nat.subFrom(14, arrayOfInt2, 0, paramArrayOfint2, 7);
    Nat.addWordAt(28, i, paramArrayOfint2, 21);
  }
  
  public static BigInteger toBigInteger64(long[] paramArrayOflong) {
    byte[] arrayOfByte = new byte[56];
    for (byte b = 0; b < 7; b++) {
      long l = paramArrayOflong[b];
      if (l != 0L)
        Pack.longToBigEndian(l, arrayOfByte, 6 - b << 3); 
    } 
    return new BigInteger(1, arrayOfByte);
  }
}
