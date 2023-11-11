package org.bouncycastle.math.ec;

import java.math.BigInteger;

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
    final int confWidth = Math.min(16, getWindowSize(i) + 3);
    eCCurve.precompute(paramECPoint, "bc_wnaf", new PreCompCallback() {
          public PreCompInfo precompute(PreCompInfo param1PreCompInfo) {
            WNafPreCompInfo wNafPreCompInfo1 = (param1PreCompInfo instanceof WNafPreCompInfo) ? (WNafPreCompInfo)param1PreCompInfo : null;
            if (null != wNafPreCompInfo1 && wNafPreCompInfo1.getConfWidth() == confWidth) {
              wNafPreCompInfo1.setPromotionCountdown(0);
              return wNafPreCompInfo1;
            } 
            WNafPreCompInfo wNafPreCompInfo2 = new WNafPreCompInfo();
            wNafPreCompInfo2.setPromotionCountdown(0);
            wNafPreCompInfo2.setConfWidth(confWidth);
            if (null != wNafPreCompInfo1) {
              wNafPreCompInfo2.setPreComp(wNafPreCompInfo1.getPreComp());
              wNafPreCompInfo2.setPreCompNeg(wNafPreCompInfo1.getPreCompNeg());
              wNafPreCompInfo2.setTwice(wNafPreCompInfo1.getTwice());
              wNafPreCompInfo2.setWidth(wNafPreCompInfo1.getWidth());
            } 
            return wNafPreCompInfo2;
          }
        });
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
    byte b1 = 0;
    byte b2 = 0;
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
    int m;
    for (m = 0; m <= paramBigInteger.bitLength(); m = paramInt) {
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
    } 
    if (arrayOfInt.length > b)
      arrayOfInt = trim(arrayOfInt, b); 
    return arrayOfInt;
  }
  
  public static byte[] generateJSF(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    int i = Math.max(paramBigInteger1.bitLength(), paramBigInteger2.bitLength()) + 1;
    byte[] arrayOfByte = new byte[i];
    BigInteger bigInteger1 = paramBigInteger1;
    BigInteger bigInteger2 = paramBigInteger2;
    byte b1 = 0;
    int j = 0;
    int k = 0;
    byte b2 = 0;
    while (true) {
      if ((j | k) != 0 || bigInteger1.bitLength() > b2 || bigInteger2.bitLength() > b2) {
        int m = (bigInteger1.intValue() >>> b2) + j & 0x7;
        int n = (bigInteger2.intValue() >>> b2) + k & 0x7;
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
        continue;
      } 
      if (arrayOfByte.length > b1)
        arrayOfByte = trim(arrayOfByte, b1); 
      return arrayOfByte;
    } 
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
    int m = 0;
    int n;
    for (n = 0; n <= paramBigInteger.bitLength(); n = paramInt) {
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
    byte b;
    for (b = 0; b < paramArrayOfint.length && paramInt1 >= paramArrayOfint[b]; b++);
    return Math.max(2, Math.min(paramInt2, b + 2));
  }
  
  public static WNafPreCompInfo precompute(final ECPoint p, final int minWidth, final boolean includeNegated) {
    final ECCurve c = p.getCurve();
    return (WNafPreCompInfo)eCCurve.precompute(p, "bc_wnaf", new PreCompCallback() {
          public PreCompInfo precompute(PreCompInfo param1PreCompInfo) {
            WNafPreCompInfo wNafPreCompInfo1 = (param1PreCompInfo instanceof WNafPreCompInfo) ? (WNafPreCompInfo)param1PreCompInfo : null;
            int i = Math.max(2, Math.min(16, minWidth));
            int j = 1 << i - 2;
            if (checkExisting(wNafPreCompInfo1, i, j, includeNegated)) {
              wNafPreCompInfo1.decrementPromotionCountdown();
              return wNafPreCompInfo1;
            } 
            WNafPreCompInfo wNafPreCompInfo2 = new WNafPreCompInfo();
            ECPoint[] arrayOfECPoint1 = null;
            ECPoint[] arrayOfECPoint2 = null;
            ECPoint eCPoint = null;
            if (null != wNafPreCompInfo1) {
              int m = wNafPreCompInfo1.decrementPromotionCountdown();
              wNafPreCompInfo2.setPromotionCountdown(m);
              int n = wNafPreCompInfo1.getConfWidth();
              wNafPreCompInfo2.setConfWidth(n);
              arrayOfECPoint1 = wNafPreCompInfo1.getPreComp();
              arrayOfECPoint2 = wNafPreCompInfo1.getPreCompNeg();
              eCPoint = wNafPreCompInfo1.getTwice();
            } 
            i = Math.min(16, Math.max(wNafPreCompInfo2.getConfWidth(), i));
            j = 1 << i - 2;
            int k = 0;
            if (null == arrayOfECPoint1) {
              arrayOfECPoint1 = WNafUtil.EMPTY_POINTS;
            } else {
              k = arrayOfECPoint1.length;
            } 
            if (k < j) {
              arrayOfECPoint1 = WNafUtil.resizeTable(arrayOfECPoint1, j);
              if (j == 1) {
                arrayOfECPoint1[0] = p.normalize();
              } else {
                int m = k;
                if (m == 0) {
                  arrayOfECPoint1[0] = p;
                  m = 1;
                } 
                ECFieldElement eCFieldElement = null;
                if (j == 2) {
                  arrayOfECPoint1[1] = p.threeTimes();
                } else {
                  ECPoint eCPoint1 = eCPoint;
                  ECPoint eCPoint2 = arrayOfECPoint1[m - 1];
                  if (null == eCPoint1) {
                    eCPoint1 = arrayOfECPoint1[0].twice();
                    eCPoint = eCPoint1;
                    if (!eCPoint.isInfinity() && ECAlgorithms.isFpCurve(c) && c.getFieldSize() >= 64) {
                      ECFieldElement eCFieldElement1;
                      ECFieldElement eCFieldElement2;
                      switch (c.getCoordinateSystem()) {
                        case 2:
                        case 3:
                        case 4:
                          eCFieldElement = eCPoint.getZCoord(0);
                          eCPoint1 = c.createPoint(eCPoint.getXCoord().toBigInteger(), eCPoint.getYCoord().toBigInteger());
                          eCFieldElement1 = eCFieldElement.square();
                          eCFieldElement2 = eCFieldElement1.multiply(eCFieldElement);
                          eCPoint2 = eCPoint2.scaleX(eCFieldElement1).scaleY(eCFieldElement2);
                          if (k == 0)
                            arrayOfECPoint1[0] = eCPoint2; 
                          break;
                      } 
                    } 
                  } 
                  while (m < j)
                    arrayOfECPoint1[m++] = eCPoint2 = eCPoint2.add(eCPoint1); 
                } 
                c.normalizeAll(arrayOfECPoint1, k, j - k, eCFieldElement);
              } 
            } 
            if (includeNegated) {
              int m;
              if (null == arrayOfECPoint2) {
                m = 0;
                arrayOfECPoint2 = new ECPoint[j];
              } else {
                m = arrayOfECPoint2.length;
                if (m < j)
                  arrayOfECPoint2 = WNafUtil.resizeTable(arrayOfECPoint2, j); 
              } 
              while (m < j) {
                arrayOfECPoint2[m] = arrayOfECPoint1[m].negate();
                m++;
              } 
            } 
            wNafPreCompInfo2.setPreComp(arrayOfECPoint1);
            wNafPreCompInfo2.setPreCompNeg(arrayOfECPoint2);
            wNafPreCompInfo2.setTwice(eCPoint);
            wNafPreCompInfo2.setWidth(i);
            return wNafPreCompInfo2;
          }
          
          private boolean checkExisting(WNafPreCompInfo param1WNafPreCompInfo, int param1Int1, int param1Int2, boolean param1Boolean) {
            return (null != param1WNafPreCompInfo && param1WNafPreCompInfo.getWidth() >= Math.max(param1WNafPreCompInfo.getConfWidth(), param1Int1) && checkTable(param1WNafPreCompInfo.getPreComp(), param1Int2) && (!param1Boolean || checkTable(param1WNafPreCompInfo.getPreCompNeg(), param1Int2)));
          }
          
          private boolean checkTable(ECPoint[] param1ArrayOfECPoint, int param1Int) {
            return (null != param1ArrayOfECPoint && param1ArrayOfECPoint.length >= param1Int);
          }
        });
  }
  
  public static WNafPreCompInfo precomputeWithPointMap(ECPoint paramECPoint, final ECPointMap pointMap, final WNafPreCompInfo fromWNaf, final boolean includeNegated) {
    ECCurve eCCurve = paramECPoint.getCurve();
    return (WNafPreCompInfo)eCCurve.precompute(paramECPoint, "bc_wnaf", new PreCompCallback() {
          public PreCompInfo precompute(PreCompInfo param1PreCompInfo) {
            WNafPreCompInfo wNafPreCompInfo1 = (param1PreCompInfo instanceof WNafPreCompInfo) ? (WNafPreCompInfo)param1PreCompInfo : null;
            int i = fromWNaf.getWidth();
            int j = (fromWNaf.getPreComp()).length;
            if (checkExisting(wNafPreCompInfo1, i, j, includeNegated)) {
              wNafPreCompInfo1.decrementPromotionCountdown();
              return wNafPreCompInfo1;
            } 
            WNafPreCompInfo wNafPreCompInfo2 = new WNafPreCompInfo();
            wNafPreCompInfo2.setPromotionCountdown(fromWNaf.getPromotionCountdown());
            ECPoint eCPoint = fromWNaf.getTwice();
            if (null != eCPoint) {
              ECPoint eCPoint1 = pointMap.map(eCPoint);
              wNafPreCompInfo2.setTwice(eCPoint1);
            } 
            ECPoint[] arrayOfECPoint1 = fromWNaf.getPreComp();
            ECPoint[] arrayOfECPoint2 = new ECPoint[arrayOfECPoint1.length];
            for (byte b = 0; b < arrayOfECPoint1.length; b++)
              arrayOfECPoint2[b] = pointMap.map(arrayOfECPoint1[b]); 
            wNafPreCompInfo2.setPreComp(arrayOfECPoint2);
            wNafPreCompInfo2.setWidth(i);
            if (includeNegated) {
              ECPoint[] arrayOfECPoint = new ECPoint[arrayOfECPoint2.length];
              for (byte b1 = 0; b1 < arrayOfECPoint.length; b1++)
                arrayOfECPoint[b1] = arrayOfECPoint2[b1].negate(); 
              wNafPreCompInfo2.setPreCompNeg(arrayOfECPoint);
            } 
            return wNafPreCompInfo2;
          }
          
          private boolean checkExisting(WNafPreCompInfo param1WNafPreCompInfo, int param1Int1, int param1Int2, boolean param1Boolean) {
            return (null != param1WNafPreCompInfo && param1WNafPreCompInfo.getWidth() >= param1Int1 && checkTable(param1WNafPreCompInfo.getPreComp(), param1Int2) && (!param1Boolean || checkTable(param1WNafPreCompInfo.getPreCompNeg(), param1Int2)));
          }
          
          private boolean checkTable(ECPoint[] param1ArrayOfECPoint, int param1Int) {
            return (null != param1ArrayOfECPoint && param1ArrayOfECPoint.length >= param1Int);
          }
        });
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
