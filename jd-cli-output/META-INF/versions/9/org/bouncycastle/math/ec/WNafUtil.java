package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPointMap;
import org.bouncycastle.math.ec.PreCompCallback;
import org.bouncycastle.math.ec.PreCompInfo;
import org.bouncycastle.math.ec.WNafPreCompInfo;

public abstract class WNafUtil {
  public static final String PRECOMP_NAME = "bc_wnaf";
  
  private static final int[] DEFAULT_WINDOW_SIZE_CUTOFFS = new int[] { 13, 41, 121, 337, 897, 2305 };
  
  private static final int MAX_WIDTH = 16;
  
  private static final byte[] EMPTY_BYTES = new byte[0];
  
  private static final int[] EMPTY_INTS = new int[0];
  
  private static final ECPoint[] EMPTY_POINTS = new ECPoint[0];
  
  public static void configureBasepoint(ECPoint paramECPoint) {
    ECCurve eCCurve = paramECPoint.getCurve();
    if (null == eCCurve)
      return; 
    BigInteger bigInteger = eCCurve.getOrder();
    int i = (null == bigInteger) ? (eCCurve.getFieldSize() + 1) : bigInteger.bitLength();
    int j = Math.min(16, getWindowSize(i) + 3);
    eCCurve.precompute(paramECPoint, "bc_wnaf", (PreCompCallback)new Object(j));
  }
  
  public static int[] generateCompactNaf(BigInteger paramBigInteger) {
    if (paramBigInteger.bitLength() >>> 16 != 0)
      throw new IllegalArgumentException("'k' must have bitlength < 2^16"); 
    if (paramBigInteger.signum() == 0)
      return EMPTY_INTS; 
    BigInteger bigInteger1 = paramBigInteger.shiftLeft(1).add(paramBigInteger);
    int i = bigInteger1.bitLength();
    int[] arrayOfInt = new int[i >> 1];
    BigInteger bigInteger2 = bigInteger1.xor(paramBigInteger);
    int j = i - 1;
    byte b1 = 0, b2 = 0;
    for (byte b3 = 1; b3 < j; b3++) {
      if (!bigInteger2.testBit(b3)) {
        b2++;
      } else {
        byte b = paramBigInteger.testBit(b3) ? -1 : 1;
        arrayOfInt[b1++] = b << 16 | b2;
        b2 = 1;
        b3++;
      } 
    } 
    arrayOfInt[b1++] = 0x10000 | b2;
    if (arrayOfInt.length > b1)
      arrayOfInt = trim(arrayOfInt, b1); 
    return arrayOfInt;
  }
  
  public static int[] generateCompactWindowNaf(int paramInt, BigInteger paramBigInteger) {
    if (paramInt == 2)
      return generateCompactNaf(paramBigInteger); 
    if (paramInt < 2 || paramInt > 16)
      throw new IllegalArgumentException("'width' must be in the range [2, 16]"); 
    if (paramBigInteger.bitLength() >>> 16 != 0)
      throw new IllegalArgumentException("'k' must have bitlength < 2^16"); 
    if (paramBigInteger.signum() == 0)
      return EMPTY_INTS; 
    int[] arrayOfInt = new int[paramBigInteger.bitLength() / paramInt + 1];
    int i = 1 << paramInt;
    int j = i - 1;
    int k = i >>> 1;
    boolean bool = false;
    byte b = 0;
    int m = 0;
    while (m <= paramBigInteger.bitLength()) {
      if (paramBigInteger.testBit(m) == bool) {
        m++;
        continue;
      } 
      paramBigInteger = paramBigInteger.shiftRight(m);
      int n = paramBigInteger.intValue() & j;
      if (bool)
        n++; 
      bool = ((n & k) != 0);
      if (bool)
        n -= i; 
      boolean bool1 = b ? (m - 1) : m;
      arrayOfInt[b++] = n << 16 | bool1;
      m = paramInt;
    } 
    if (arrayOfInt.length > b)
      arrayOfInt = trim(arrayOfInt, b); 
    return arrayOfInt;
  }
  
  public static byte[] generateJSF(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    int i = Math.max(paramBigInteger1.bitLength(), paramBigInteger2.bitLength()) + 1;
    byte[] arrayOfByte = new byte[i];
    BigInteger bigInteger1 = paramBigInteger1, bigInteger2 = paramBigInteger2;
    byte b1 = 0;
    int j = 0, k = 0;
    byte b2 = 0;
    while ((j | k) != 0 || bigInteger1.bitLength() > b2 || bigInteger2.bitLength() > b2) {
      int m = (bigInteger1.intValue() >>> b2) + j & 0x7, n = (bigInteger2.intValue() >>> b2) + k & 0x7;
      int i1 = m & 0x1;
      if (i1 != 0) {
        i1 -= m & 0x2;
        if (m + i1 == 4 && (n & 0x3) == 2)
          i1 = -i1; 
      } 
      int i2 = n & 0x1;
      if (i2 != 0) {
        i2 -= n & 0x2;
        if (n + i2 == 4 && (m & 0x3) == 2)
          i2 = -i2; 
      } 
      if (j << 1 == 1 + i1)
        j ^= 0x1; 
      if (k << 1 == 1 + i2)
        k ^= 0x1; 
      if (++b2 == 30) {
        b2 = 0;
        bigInteger1 = bigInteger1.shiftRight(30);
        bigInteger2 = bigInteger2.shiftRight(30);
      } 
      arrayOfByte[b1++] = (byte)(i1 << 4 | i2 & 0xF);
    } 
    if (arrayOfByte.length > b1)
      arrayOfByte = trim(arrayOfByte, b1); 
    return arrayOfByte;
  }
  
  public static byte[] generateNaf(BigInteger paramBigInteger) {
    if (paramBigInteger.signum() == 0)
      return EMPTY_BYTES; 
    BigInteger bigInteger1 = paramBigInteger.shiftLeft(1).add(paramBigInteger);
    int i = bigInteger1.bitLength() - 1;
    byte[] arrayOfByte = new byte[i];
    BigInteger bigInteger2 = bigInteger1.xor(paramBigInteger);
    for (byte b = 1; b < i; b++) {
      if (bigInteger2.testBit(b)) {
        arrayOfByte[b - 1] = (byte)(paramBigInteger.testBit(b) ? -1 : 1);
        b++;
      } 
    } 
    arrayOfByte[i - 1] = 1;
    return arrayOfByte;
  }
  
  public static byte[] generateWindowNaf(int paramInt, BigInteger paramBigInteger) {
    if (paramInt == 2)
      return generateNaf(paramBigInteger); 
    if (paramInt < 2 || paramInt > 8)
      throw new IllegalArgumentException("'width' must be in the range [2, 8]"); 
    if (paramBigInteger.signum() == 0)
      return EMPTY_BYTES; 
    byte[] arrayOfByte = new byte[paramBigInteger.bitLength() + 1];
    int i = 1 << paramInt;
    int j = i - 1;
    int k = i >>> 1;
    boolean bool = false;
    int m = 0, n = 0;
    while (n <= paramBigInteger.bitLength()) {
      if (paramBigInteger.testBit(n) == bool) {
        n++;
        continue;
      } 
      paramBigInteger = paramBigInteger.shiftRight(n);
      int i1 = paramBigInteger.intValue() & j;
      if (bool)
        i1++; 
      bool = ((i1 & k) != 0);
      if (bool)
        i1 -= i; 
      m += m ? (n - 1) : n;
      arrayOfByte[m++] = (byte)i1;
      n = paramInt;
    } 
    if (arrayOfByte.length > m)
      arrayOfByte = trim(arrayOfByte, m); 
    return arrayOfByte;
  }
  
  public static int getNafWeight(BigInteger paramBigInteger) {
    if (paramBigInteger.signum() == 0)
      return 0; 
    BigInteger bigInteger1 = paramBigInteger.shiftLeft(1).add(paramBigInteger);
    BigInteger bigInteger2 = bigInteger1.xor(paramBigInteger);
    return bigInteger2.bitCount();
  }
  
  public static WNafPreCompInfo getWNafPreCompInfo(ECPoint paramECPoint) {
    return getWNafPreCompInfo(paramECPoint.getCurve().getPreCompInfo(paramECPoint, "bc_wnaf"));
  }
  
  public static WNafPreCompInfo getWNafPreCompInfo(PreCompInfo paramPreCompInfo) {
    return (paramPreCompInfo instanceof WNafPreCompInfo) ? (WNafPreCompInfo)paramPreCompInfo : null;
  }
  
  public static int getWindowSize(int paramInt) {
    return getWindowSize(paramInt, DEFAULT_WINDOW_SIZE_CUTOFFS, 16);
  }
  
  public static int getWindowSize(int paramInt1, int paramInt2) {
    return getWindowSize(paramInt1, DEFAULT_WINDOW_SIZE_CUTOFFS, paramInt2);
  }
  
  public static int getWindowSize(int paramInt, int[] paramArrayOfint) {
    return getWindowSize(paramInt, paramArrayOfint, 16);
  }
  
  public static int getWindowSize(int paramInt1, int[] paramArrayOfint, int paramInt2) {
    byte b = 0;
    for (; b < paramArrayOfint.length; b++) {
      if (paramInt1 < paramArrayOfint[b])
        break; 
    } 
    return Math.max(2, Math.min(paramInt2, b + 2));
  }
  
  public static WNafPreCompInfo precompute(ECPoint paramECPoint, int paramInt, boolean paramBoolean) {
    ECCurve eCCurve = paramECPoint.getCurve();
    return (WNafPreCompInfo)eCCurve.precompute(paramECPoint, "bc_wnaf", (PreCompCallback)new Object(paramInt, paramBoolean, paramECPoint, eCCurve));
  }
  
  public static WNafPreCompInfo precomputeWithPointMap(ECPoint paramECPoint, ECPointMap paramECPointMap, WNafPreCompInfo paramWNafPreCompInfo, boolean paramBoolean) {
    ECCurve eCCurve = paramECPoint.getCurve();
    return (WNafPreCompInfo)eCCurve.precompute(paramECPoint, "bc_wnaf", (PreCompCallback)new Object(paramWNafPreCompInfo, paramBoolean, paramECPointMap));
  }
  
  private static byte[] trim(byte[] paramArrayOfbyte, int paramInt) {
    byte[] arrayOfByte = new byte[paramInt];
    System.arraycopy(paramArrayOfbyte, 0, arrayOfByte, 0, arrayOfByte.length);
    return arrayOfByte;
  }
  
  private static int[] trim(int[] paramArrayOfint, int paramInt) {
    int[] arrayOfInt = new int[paramInt];
    System.arraycopy(paramArrayOfint, 0, arrayOfInt, 0, arrayOfInt.length);
    return arrayOfInt;
  }
  
  private static ECPoint[] resizeTable(ECPoint[] paramArrayOfECPoint, int paramInt) {
    ECPoint[] arrayOfECPoint = new ECPoint[paramInt];
    System.arraycopy(paramArrayOfECPoint, 0, arrayOfECPoint, 0, paramArrayOfECPoint.length);
    return arrayOfECPoint;
  }
}
