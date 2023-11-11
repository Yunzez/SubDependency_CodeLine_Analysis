package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat160;
import org.bouncycastle.util.Pack;

public class SecP160R2Field {
  static final int[] P = new int[] { -21389, -2, -1, -1, -1 };
  
  private static final int[] PExt = new int[] { 457489321, 42778, 1, 0, 0, -42778, -3, -1, -1, -1 };
  
  private static final int[] PExtInv = new int[] { -457489321, -42779, -2, -1, -1, 42777, 2 };
  
  private static final int P4 = -1;
  
  private static final int PExt9 = -1;
  
  private static final int PInv33 = 21389;
  
  public static void add(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int i = Nat160.add(paramArrayOfint1, paramArrayOfint2, paramArrayOfint3);
    if (i != 0 || (paramArrayOfint3[4] == -1 && Nat160.gte(paramArrayOfint3, P)))
      Nat.add33To(5, 21389, paramArrayOfint3); 
  }
  
  public static void addExt(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int i = Nat.add(10, paramArrayOfint1, paramArrayOfint2, paramArrayOfint3);
    if ((i != 0 || (paramArrayOfint3[9] == -1 && Nat.gte(10, paramArrayOfint3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, paramArrayOfint3) != 0)
      Nat.incAt(10, paramArrayOfint3, PExtInv.length); 
  }
  
  public static void addOne(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = Nat.inc(5, paramArrayOfint1, paramArrayOfint2);
    if (i != 0 || (paramArrayOfint2[4] == -1 && Nat160.gte(paramArrayOfint2, P)))
      Nat.add33To(5, 21389, paramArrayOfint2); 
  }
  
  public static int[] fromBigInteger(BigInteger paramBigInteger) {
    int[] arrayOfInt = Nat160.fromBigInteger(paramBigInteger);
    if (arrayOfInt[4] == -1 && Nat160.gte(arrayOfInt, P))
      Nat160.subFrom(P, arrayOfInt); 
    return arrayOfInt;
  }
  
  public static void half(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    if ((paramArrayOfint1[0] & 0x1) == 0) {
      Nat.shiftDownBit(5, paramArrayOfint1, 0, paramArrayOfint2);
    } else {
      int i = Nat160.add(paramArrayOfint1, P, paramArrayOfint2);
      Nat.shiftDownBit(5, paramArrayOfint2, i);
    } 
  }
  
  public static void inv(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    Mod.checkedModOddInverse(P, paramArrayOfint1, paramArrayOfint2);
  }
  
  public static int isZero(int[] paramArrayOfint) {
    int i = 0;
    for (byte b = 0; b < 5; b++)
      i |= paramArrayOfint[b]; 
    i = i >>> 1 | i & 0x1;
    return i - 1 >> 31;
  }
  
  public static void multiply(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int[] arrayOfInt = Nat160.createExt();
    Nat160.mul(paramArrayOfint1, paramArrayOfint2, arrayOfInt);
    reduce(arrayOfInt, paramArrayOfint3);
  }
  
  public static void multiplyAddToExt(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int i = Nat160.mulAddTo(paramArrayOfint1, paramArrayOfint2, paramArrayOfint3);
    if ((i != 0 || (paramArrayOfint3[9] == -1 && Nat.gte(10, paramArrayOfint3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, paramArrayOfint3) != 0)
      Nat.incAt(10, paramArrayOfint3, PExtInv.length); 
  }
  
  public static void negate(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    if (0 != isZero(paramArrayOfint1)) {
      Nat160.sub(P, P, paramArrayOfint2);
    } else {
      Nat160.sub(P, paramArrayOfint1, paramArrayOfint2);
    } 
  }
  
  public static void random(SecureRandom paramSecureRandom, int[] paramArrayOfint) {
    byte[] arrayOfByte = new byte[20];
    do {
      paramSecureRandom.nextBytes(arrayOfByte);
      Pack.littleEndianToInt(arrayOfByte, 0, paramArrayOfint, 0, 5);
    } while (0 == Nat.lessThan(5, paramArrayOfint, P));
  }
  
  public static void randomMult(SecureRandom paramSecureRandom, int[] paramArrayOfint) {
    do {
      random(paramSecureRandom, paramArrayOfint);
    } while (0 != isZero(paramArrayOfint));
  }
  
  public static void reduce(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    long l = Nat160.mul33Add(21389, paramArrayOfint1, 5, paramArrayOfint1, 0, paramArrayOfint2, 0);
    int i = Nat160.mul33DWordAdd(21389, l, paramArrayOfint2, 0);
    if (i != 0 || (paramArrayOfint2[4] == -1 && Nat160.gte(paramArrayOfint2, P)))
      Nat.add33To(5, 21389, paramArrayOfint2); 
  }
  
  public static void reduce32(int paramInt, int[] paramArrayOfint) {
    if ((paramInt != 0 && Nat160.mul33WordAdd(21389, paramInt, paramArrayOfint, 0) != 0) || (paramArrayOfint[4] == -1 && Nat160.gte(paramArrayOfint, P)))
      Nat.add33To(5, 21389, paramArrayOfint); 
  }
  
  public static void square(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int[] arrayOfInt = Nat160.createExt();
    Nat160.square(paramArrayOfint1, arrayOfInt);
    reduce(arrayOfInt, paramArrayOfint2);
  }
  
  public static void squareN(int[] paramArrayOfint1, int paramInt, int[] paramArrayOfint2) {
    int[] arrayOfInt = Nat160.createExt();
    Nat160.square(paramArrayOfint1, arrayOfInt);
    reduce(arrayOfInt, paramArrayOfint2);
    while (--paramInt > 0) {
      Nat160.square(paramArrayOfint2, arrayOfInt);
      reduce(arrayOfInt, paramArrayOfint2);
    } 
  }
  
  public static void subtract(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int i = Nat160.sub(paramArrayOfint1, paramArrayOfint2, paramArrayOfint3);
    if (i != 0)
      Nat.sub33From(5, 21389, paramArrayOfint3); 
  }
  
  public static void subtractExt(int[] paramArrayOfint1, int[] paramArrayOfint2, int[] paramArrayOfint3) {
    int i = Nat.sub(10, paramArrayOfint1, paramArrayOfint2, paramArrayOfint3);
    if (i != 0 && Nat.subFrom(PExtInv.length, PExtInv, paramArrayOfint3) != 0)
      Nat.decAt(10, paramArrayOfint3, PExtInv.length); 
  }
  
  public static void twice(int[] paramArrayOfint1, int[] paramArrayOfint2) {
    int i = Nat.shiftUpBit(5, paramArrayOfint1, 0, paramArrayOfint2);
    if (i != 0 || (paramArrayOfint2[4] == -1 && Nat160.gte(paramArrayOfint2, P)))
      Nat.add33To(5, 21389, paramArrayOfint2); 
  }
}
