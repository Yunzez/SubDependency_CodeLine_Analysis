package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECPointMap;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.FixedPointPreCompInfo;
import org.bouncycastle.math.ec.FixedPointUtil;
import org.bouncycastle.math.ec.WNafPreCompInfo;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.math.ec.endo.ECEndomorphism;
import org.bouncycastle.math.ec.endo.EndoUtil;
import org.bouncycastle.math.ec.endo.GLVEndomorphism;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.raw.Nat;

public class ECAlgorithms {
  public static boolean isF2mCurve(ECCurve paramECCurve) {
    return isF2mField(paramECCurve.getField());
  }
  
  public static boolean isF2mField(FiniteField paramFiniteField) {
    return (paramFiniteField.getDimension() > 1 && paramFiniteField.getCharacteristic().equals(ECConstants.TWO) && paramFiniteField instanceof org.bouncycastle.math.field.PolynomialExtensionField);
  }
  
  public static boolean isFpCurve(ECCurve paramECCurve) {
    return isFpField(paramECCurve.getField());
  }
  
  public static boolean isFpField(FiniteField paramFiniteField) {
    return (paramFiniteField.getDimension() == 1);
  }
  
  public static ECPoint sumOfMultiplies(ECPoint[] paramArrayOfECPoint, BigInteger[] paramArrayOfBigInteger) {
    if (paramArrayOfECPoint == null || paramArrayOfBigInteger == null || paramArrayOfECPoint.length != paramArrayOfBigInteger.length || paramArrayOfECPoint.length < 1)
      throw new IllegalArgumentException("point and scalar arrays should be non-null, and of equal, non-zero, length"); 
    int i = paramArrayOfECPoint.length;
    switch (i) {
      case 1:
        return paramArrayOfECPoint[0].multiply(paramArrayOfBigInteger[0]);
      case 2:
        return sumOfTwoMultiplies(paramArrayOfECPoint[0], paramArrayOfBigInteger[0], paramArrayOfECPoint[1], paramArrayOfBigInteger[1]);
    } 
    ECPoint eCPoint = paramArrayOfECPoint[0];
    ECCurve eCCurve = eCPoint.getCurve();
    ECPoint[] arrayOfECPoint = new ECPoint[i];
    arrayOfECPoint[0] = eCPoint;
    for (byte b = 1; b < i; b++)
      arrayOfECPoint[b] = importPoint(eCCurve, paramArrayOfECPoint[b]); 
    ECEndomorphism eCEndomorphism = eCCurve.getEndomorphism();
    if (eCEndomorphism instanceof GLVEndomorphism)
      return implCheckResult(implSumOfMultipliesGLV(arrayOfECPoint, paramArrayOfBigInteger, (GLVEndomorphism)eCEndomorphism)); 
    return implCheckResult(implSumOfMultiplies(arrayOfECPoint, paramArrayOfBigInteger));
  }
  
  public static ECPoint sumOfTwoMultiplies(ECPoint paramECPoint1, BigInteger paramBigInteger1, ECPoint paramECPoint2, BigInteger paramBigInteger2) {
    ECCurve eCCurve = paramECPoint1.getCurve();
    paramECPoint2 = importPoint(eCCurve, paramECPoint2);
    if (eCCurve instanceof ECCurve.AbstractF2m) {
      ECCurve.AbstractF2m abstractF2m = (ECCurve.AbstractF2m)eCCurve;
      if (abstractF2m.isKoblitz())
        return implCheckResult(paramECPoint1.multiply(paramBigInteger1).add(paramECPoint2.multiply(paramBigInteger2))); 
    } 
    ECEndomorphism eCEndomorphism = eCCurve.getEndomorphism();
    if (eCEndomorphism instanceof GLVEndomorphism)
      return implCheckResult(
          implSumOfMultipliesGLV(new ECPoint[] { paramECPoint1, paramECPoint2 }, new BigInteger[] { paramBigInteger1, paramBigInteger2 }, (GLVEndomorphism)eCEndomorphism)); 
    return implCheckResult(implShamirsTrickWNaf(paramECPoint1, paramBigInteger1, paramECPoint2, paramBigInteger2));
  }
  
  public static ECPoint shamirsTrick(ECPoint paramECPoint1, BigInteger paramBigInteger1, ECPoint paramECPoint2, BigInteger paramBigInteger2) {
    ECCurve eCCurve = paramECPoint1.getCurve();
    paramECPoint2 = importPoint(eCCurve, paramECPoint2);
    return implCheckResult(implShamirsTrickJsf(paramECPoint1, paramBigInteger1, paramECPoint2, paramBigInteger2));
  }
  
  public static ECPoint importPoint(ECCurve paramECCurve, ECPoint paramECPoint) {
    ECCurve eCCurve = paramECPoint.getCurve();
    if (!paramECCurve.equals(eCCurve))
      throw new IllegalArgumentException("Point must be on the same curve"); 
    return paramECCurve.importPoint(paramECPoint);
  }
  
  public static void montgomeryTrick(ECFieldElement[] paramArrayOfECFieldElement, int paramInt1, int paramInt2) {
    montgomeryTrick(paramArrayOfECFieldElement, paramInt1, paramInt2, null);
  }
  
  public static void montgomeryTrick(ECFieldElement[] paramArrayOfECFieldElement, int paramInt1, int paramInt2, ECFieldElement paramECFieldElement) {
    ECFieldElement[] arrayOfECFieldElement = new ECFieldElement[paramInt2];
    arrayOfECFieldElement[0] = paramArrayOfECFieldElement[paramInt1];
    byte b = 0;
    while (++b < paramInt2)
      arrayOfECFieldElement[b] = arrayOfECFieldElement[b - 1].multiply(paramArrayOfECFieldElement[paramInt1 + b]); 
    b--;
    if (paramECFieldElement != null)
      arrayOfECFieldElement[b] = arrayOfECFieldElement[b].multiply(paramECFieldElement); 
    ECFieldElement eCFieldElement = arrayOfECFieldElement[b].invert();
    while (b > 0) {
      int i = paramInt1 + b--;
      ECFieldElement eCFieldElement1 = paramArrayOfECFieldElement[i];
      paramArrayOfECFieldElement[i] = arrayOfECFieldElement[b].multiply(eCFieldElement);
      eCFieldElement = eCFieldElement.multiply(eCFieldElement1);
    } 
    paramArrayOfECFieldElement[paramInt1] = eCFieldElement;
  }
  
  public static ECPoint referenceMultiply(ECPoint paramECPoint, BigInteger paramBigInteger) {
    BigInteger bigInteger = paramBigInteger.abs();
    ECPoint eCPoint = paramECPoint.getCurve().getInfinity();
    int i = bigInteger.bitLength();
    if (i > 0) {
      if (bigInteger.testBit(0))
        eCPoint = paramECPoint; 
      for (byte b = 1; b < i; b++) {
        paramECPoint = paramECPoint.twice();
        if (bigInteger.testBit(b))
          eCPoint = eCPoint.add(paramECPoint); 
      } 
    } 
    return (paramBigInteger.signum() < 0) ? eCPoint.negate() : eCPoint;
  }
  
  public static ECPoint validatePoint(ECPoint paramECPoint) {
    if (!paramECPoint.isValid())
      throw new IllegalStateException("Invalid point"); 
    return paramECPoint;
  }
  
  public static ECPoint cleanPoint(ECCurve paramECCurve, ECPoint paramECPoint) {
    ECCurve eCCurve = paramECPoint.getCurve();
    if (!paramECCurve.equals(eCCurve))
      throw new IllegalArgumentException("Point must be on the same curve"); 
    return paramECCurve.decodePoint(paramECPoint.getEncoded(false));
  }
  
  static ECPoint implCheckResult(ECPoint paramECPoint) {
    if (!paramECPoint.isValidPartial())
      throw new IllegalStateException("Invalid result"); 
    return paramECPoint;
  }
  
  static ECPoint implShamirsTrickJsf(ECPoint paramECPoint1, BigInteger paramBigInteger1, ECPoint paramECPoint2, BigInteger paramBigInteger2) {
    ECCurve eCCurve = paramECPoint1.getCurve();
    ECPoint eCPoint1 = eCCurve.getInfinity();
    ECPoint eCPoint2 = paramECPoint1.add(paramECPoint2);
    ECPoint eCPoint3 = paramECPoint1.subtract(paramECPoint2);
    ECPoint[] arrayOfECPoint1 = { paramECPoint2, eCPoint3, paramECPoint1, eCPoint2 };
    eCCurve.normalizeAll(arrayOfECPoint1);
    ECPoint[] arrayOfECPoint2 = { arrayOfECPoint1[3].negate(), arrayOfECPoint1[2].negate(), arrayOfECPoint1[1].negate(), arrayOfECPoint1[0].negate(), eCPoint1, arrayOfECPoint1[0], arrayOfECPoint1[1], arrayOfECPoint1[2], arrayOfECPoint1[3] };
    byte[] arrayOfByte = WNafUtil.generateJSF(paramBigInteger1, paramBigInteger2);
    ECPoint eCPoint4 = eCPoint1;
    int i = arrayOfByte.length;
    while (--i >= 0) {
      byte b = arrayOfByte[i];
      int j = b << 24 >> 28, k = b << 28 >> 28;
      int m = 4 + j * 3 + k;
      eCPoint4 = eCPoint4.twicePlus(arrayOfECPoint2[m]);
    } 
    return eCPoint4;
  }
  
  static ECPoint implShamirsTrickWNaf(ECPoint paramECPoint1, BigInteger paramBigInteger1, ECPoint paramECPoint2, BigInteger paramBigInteger2) {
    boolean bool1 = (paramBigInteger1.signum() < 0) ? true : false, bool2 = (paramBigInteger2.signum() < 0) ? true : false;
    BigInteger bigInteger1 = paramBigInteger1.abs(), bigInteger2 = paramBigInteger2.abs();
    int i = WNafUtil.getWindowSize(bigInteger1.bitLength(), 8);
    int j = WNafUtil.getWindowSize(bigInteger2.bitLength(), 8);
    WNafPreCompInfo wNafPreCompInfo1 = WNafUtil.precompute(paramECPoint1, i, true);
    WNafPreCompInfo wNafPreCompInfo2 = WNafUtil.precompute(paramECPoint2, j, true);
    ECCurve eCCurve = paramECPoint1.getCurve();
    int m = FixedPointUtil.getCombSize(eCCurve);
    if (!bool1 && !bool2 && paramBigInteger1
      .bitLength() <= m && paramBigInteger2.bitLength() <= m && wNafPreCompInfo1
      .isPromoted() && wNafPreCompInfo2.isPromoted())
      return implShamirsTrickFixedPoint(paramECPoint1, paramBigInteger1, paramECPoint2, paramBigInteger2); 
    int k = Math.min(8, wNafPreCompInfo1.getWidth());
    m = Math.min(8, wNafPreCompInfo2.getWidth());
    ECPoint[] arrayOfECPoint1 = bool1 ? wNafPreCompInfo1.getPreCompNeg() : wNafPreCompInfo1.getPreComp();
    ECPoint[] arrayOfECPoint2 = bool2 ? wNafPreCompInfo2.getPreCompNeg() : wNafPreCompInfo2.getPreComp();
    ECPoint[] arrayOfECPoint3 = bool1 ? wNafPreCompInfo1.getPreComp() : wNafPreCompInfo1.getPreCompNeg();
    ECPoint[] arrayOfECPoint4 = bool2 ? wNafPreCompInfo2.getPreComp() : wNafPreCompInfo2.getPreCompNeg();
    byte[] arrayOfByte1 = WNafUtil.generateWindowNaf(k, bigInteger1);
    byte[] arrayOfByte2 = WNafUtil.generateWindowNaf(m, bigInteger2);
    return implShamirsTrickWNaf(arrayOfECPoint1, arrayOfECPoint3, arrayOfByte1, arrayOfECPoint2, arrayOfECPoint4, arrayOfByte2);
  }
  
  static ECPoint implShamirsTrickWNaf(ECEndomorphism paramECEndomorphism, ECPoint paramECPoint, BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    boolean bool1 = (paramBigInteger1.signum() < 0) ? true : false, bool2 = (paramBigInteger2.signum() < 0) ? true : false;
    paramBigInteger1 = paramBigInteger1.abs();
    paramBigInteger2 = paramBigInteger2.abs();
    int i = WNafUtil.getWindowSize(Math.max(paramBigInteger1.bitLength(), paramBigInteger2.bitLength()), 8);
    WNafPreCompInfo wNafPreCompInfo1 = WNafUtil.precompute(paramECPoint, i, true);
    ECPoint eCPoint = EndoUtil.mapPoint(paramECEndomorphism, paramECPoint);
    WNafPreCompInfo wNafPreCompInfo2 = WNafUtil.precomputeWithPointMap(eCPoint, paramECEndomorphism.getPointMap(), wNafPreCompInfo1, true);
    int j = Math.min(8, wNafPreCompInfo1.getWidth());
    int k = Math.min(8, wNafPreCompInfo2.getWidth());
    ECPoint[] arrayOfECPoint1 = bool1 ? wNafPreCompInfo1.getPreCompNeg() : wNafPreCompInfo1.getPreComp();
    ECPoint[] arrayOfECPoint2 = bool2 ? wNafPreCompInfo2.getPreCompNeg() : wNafPreCompInfo2.getPreComp();
    ECPoint[] arrayOfECPoint3 = bool1 ? wNafPreCompInfo1.getPreComp() : wNafPreCompInfo1.getPreCompNeg();
    ECPoint[] arrayOfECPoint4 = bool2 ? wNafPreCompInfo2.getPreComp() : wNafPreCompInfo2.getPreCompNeg();
    byte[] arrayOfByte1 = WNafUtil.generateWindowNaf(j, paramBigInteger1);
    byte[] arrayOfByte2 = WNafUtil.generateWindowNaf(k, paramBigInteger2);
    return implShamirsTrickWNaf(arrayOfECPoint1, arrayOfECPoint3, arrayOfByte1, arrayOfECPoint2, arrayOfECPoint4, arrayOfByte2);
  }
  
  private static ECPoint implShamirsTrickWNaf(ECPoint[] paramArrayOfECPoint1, ECPoint[] paramArrayOfECPoint2, byte[] paramArrayOfbyte1, ECPoint[] paramArrayOfECPoint3, ECPoint[] paramArrayOfECPoint4, byte[] paramArrayOfbyte2) {
    int i = Math.max(paramArrayOfbyte1.length, paramArrayOfbyte2.length);
    ECCurve eCCurve = paramArrayOfECPoint1[0].getCurve();
    ECPoint eCPoint1 = eCCurve.getInfinity();
    ECPoint eCPoint2 = eCPoint1;
    byte b = 0;
    for (int j = i - 1; j >= 0; j--) {
      boolean bool1 = (j < paramArrayOfbyte1.length) ? paramArrayOfbyte1[j] : false;
      boolean bool2 = (j < paramArrayOfbyte2.length) ? paramArrayOfbyte2[j] : false;
      if ((bool1 | bool2) == 0) {
        b++;
      } else {
        ECPoint eCPoint = eCPoint1;
        if (bool1) {
          int k = Math.abs(bool1);
          ECPoint[] arrayOfECPoint = bool1 ? paramArrayOfECPoint2 : paramArrayOfECPoint1;
          eCPoint = eCPoint.add(arrayOfECPoint[k >>> 1]);
        } 
        if (bool2) {
          int k = Math.abs(bool2);
          ECPoint[] arrayOfECPoint = bool2 ? paramArrayOfECPoint4 : paramArrayOfECPoint3;
          eCPoint = eCPoint.add(arrayOfECPoint[k >>> 1]);
        } 
        if (b > 0) {
          eCPoint2 = eCPoint2.timesPow2(b);
          b = 0;
        } 
        eCPoint2 = eCPoint2.twicePlus(eCPoint);
      } 
    } 
    if (b > 0)
      eCPoint2 = eCPoint2.timesPow2(b); 
    return eCPoint2;
  }
  
  static ECPoint implSumOfMultiplies(ECPoint[] paramArrayOfECPoint, BigInteger[] paramArrayOfBigInteger) {
    int i = paramArrayOfECPoint.length;
    boolean[] arrayOfBoolean = new boolean[i];
    WNafPreCompInfo[] arrayOfWNafPreCompInfo = new WNafPreCompInfo[i];
    byte[][] arrayOfByte = new byte[i][];
    for (byte b = 0; b < i; b++) {
      BigInteger bigInteger = paramArrayOfBigInteger[b];
      arrayOfBoolean[b] = (bigInteger.signum() < 0);
      bigInteger = bigInteger.abs();
      int j = WNafUtil.getWindowSize(bigInteger.bitLength(), 8);
      WNafPreCompInfo wNafPreCompInfo = WNafUtil.precompute(paramArrayOfECPoint[b], j, true);
      int k = Math.min(8, wNafPreCompInfo.getWidth());
      arrayOfWNafPreCompInfo[b] = wNafPreCompInfo;
      arrayOfByte[b] = WNafUtil.generateWindowNaf(k, bigInteger);
    } 
    return implSumOfMultiplies(arrayOfBoolean, arrayOfWNafPreCompInfo, arrayOfByte);
  }
  
  static ECPoint implSumOfMultipliesGLV(ECPoint[] paramArrayOfECPoint, BigInteger[] paramArrayOfBigInteger, GLVEndomorphism paramGLVEndomorphism) {
    BigInteger bigInteger = paramArrayOfECPoint[0].getCurve().getOrder();
    int i = paramArrayOfECPoint.length;
    BigInteger[] arrayOfBigInteger = new BigInteger[i << 1];
    byte b2;
    for (byte b1 = 0; b1 < i; b1++) {
      BigInteger[] arrayOfBigInteger1 = paramGLVEndomorphism.decomposeScalar(paramArrayOfBigInteger[b1].mod(bigInteger));
      arrayOfBigInteger[b2++] = arrayOfBigInteger1[0];
      arrayOfBigInteger[b2++] = arrayOfBigInteger1[1];
    } 
    if (paramGLVEndomorphism.hasEfficientPointMap())
      return implSumOfMultiplies(paramGLVEndomorphism, paramArrayOfECPoint, arrayOfBigInteger); 
    ECPoint[] arrayOfECPoint = new ECPoint[i << 1];
    byte b3;
    for (b2 = 0, b3 = 0; b2 < i; b2++) {
      ECPoint eCPoint1 = paramArrayOfECPoint[b2];
      ECPoint eCPoint2 = EndoUtil.mapPoint(paramGLVEndomorphism, eCPoint1);
      arrayOfECPoint[b3++] = eCPoint1;
      arrayOfECPoint[b3++] = eCPoint2;
    } 
    return implSumOfMultiplies(arrayOfECPoint, arrayOfBigInteger);
  }
  
  static ECPoint implSumOfMultiplies(ECEndomorphism paramECEndomorphism, ECPoint[] paramArrayOfECPoint, BigInteger[] paramArrayOfBigInteger) {
    int i = paramArrayOfECPoint.length, j = i << 1;
    boolean[] arrayOfBoolean = new boolean[j];
    WNafPreCompInfo[] arrayOfWNafPreCompInfo = new WNafPreCompInfo[j];
    byte[][] arrayOfByte = new byte[j][];
    ECPointMap eCPointMap = paramECEndomorphism.getPointMap();
    for (byte b = 0; b < i; b++) {
      int k = b << 1, m = k + 1;
      BigInteger bigInteger1 = paramArrayOfBigInteger[k];
      arrayOfBoolean[k] = (bigInteger1.signum() < 0);
      bigInteger1 = bigInteger1.abs();
      BigInteger bigInteger2 = paramArrayOfBigInteger[m];
      arrayOfBoolean[m] = (bigInteger2.signum() < 0);
      bigInteger2 = bigInteger2.abs();
      int n = WNafUtil.getWindowSize(Math.max(bigInteger1.bitLength(), bigInteger2.bitLength()), 8);
      ECPoint eCPoint1 = paramArrayOfECPoint[b];
      WNafPreCompInfo wNafPreCompInfo1 = WNafUtil.precompute(eCPoint1, n, true);
      ECPoint eCPoint2 = EndoUtil.mapPoint(paramECEndomorphism, eCPoint1);
      WNafPreCompInfo wNafPreCompInfo2 = WNafUtil.precomputeWithPointMap(eCPoint2, eCPointMap, wNafPreCompInfo1, true);
      int i1 = Math.min(8, wNafPreCompInfo1.getWidth());
      int i2 = Math.min(8, wNafPreCompInfo2.getWidth());
      arrayOfWNafPreCompInfo[k] = wNafPreCompInfo1;
      arrayOfWNafPreCompInfo[m] = wNafPreCompInfo2;
      arrayOfByte[k] = WNafUtil.generateWindowNaf(i1, bigInteger1);
      arrayOfByte[m] = WNafUtil.generateWindowNaf(i2, bigInteger2);
    } 
    return implSumOfMultiplies(arrayOfBoolean, arrayOfWNafPreCompInfo, arrayOfByte);
  }
  
  private static ECPoint implSumOfMultiplies(boolean[] paramArrayOfboolean, WNafPreCompInfo[] paramArrayOfWNafPreCompInfo, byte[][] paramArrayOfbyte) {
    int i = 0, j = paramArrayOfbyte.length;
    for (byte b1 = 0; b1 < j; b1++)
      i = Math.max(i, (paramArrayOfbyte[b1]).length); 
    ECCurve eCCurve = paramArrayOfWNafPreCompInfo[0].getPreComp()[0].getCurve();
    ECPoint eCPoint1 = eCCurve.getInfinity();
    ECPoint eCPoint2 = eCPoint1;
    byte b2 = 0;
    for (int k = i - 1; k >= 0; k--) {
      ECPoint eCPoint = eCPoint1;
      for (byte b = 0; b < j; b++) {
        byte[] arrayOfByte = paramArrayOfbyte[b];
        boolean bool = (k < arrayOfByte.length) ? arrayOfByte[k] : false;
        if (bool) {
          int m = Math.abs(bool);
          WNafPreCompInfo wNafPreCompInfo = paramArrayOfWNafPreCompInfo[b];
          ECPoint[] arrayOfECPoint = ((bool) == paramArrayOfboolean[b]) ? wNafPreCompInfo.getPreComp() : wNafPreCompInfo.getPreCompNeg();
          eCPoint = eCPoint.add(arrayOfECPoint[m >>> 1]);
        } 
      } 
      if (eCPoint == eCPoint1) {
        b2++;
      } else {
        if (b2 > 0) {
          eCPoint2 = eCPoint2.timesPow2(b2);
          b2 = 0;
        } 
        eCPoint2 = eCPoint2.twicePlus(eCPoint);
      } 
    } 
    if (b2 > 0)
      eCPoint2 = eCPoint2.timesPow2(b2); 
    return eCPoint2;
  }
  
  private static ECPoint implShamirsTrickFixedPoint(ECPoint paramECPoint1, BigInteger paramBigInteger1, ECPoint paramECPoint2, BigInteger paramBigInteger2) {
    ECCurve eCCurve = paramECPoint1.getCurve();
    int i = FixedPointUtil.getCombSize(eCCurve);
    if (paramBigInteger1.bitLength() > i || paramBigInteger2.bitLength() > i)
      throw new IllegalStateException("fixed-point comb doesn't support scalars larger than the curve order"); 
    FixedPointPreCompInfo fixedPointPreCompInfo1 = FixedPointUtil.precompute(paramECPoint1);
    FixedPointPreCompInfo fixedPointPreCompInfo2 = FixedPointUtil.precompute(paramECPoint2);
    ECLookupTable eCLookupTable1 = fixedPointPreCompInfo1.getLookupTable();
    ECLookupTable eCLookupTable2 = fixedPointPreCompInfo2.getLookupTable();
    int j = fixedPointPreCompInfo1.getWidth();
    int k = fixedPointPreCompInfo2.getWidth();
    if (j != k) {
      FixedPointCombMultiplier fixedPointCombMultiplier = new FixedPointCombMultiplier();
      ECPoint eCPoint1 = fixedPointCombMultiplier.multiply(paramECPoint1, paramBigInteger1);
      ECPoint eCPoint2 = fixedPointCombMultiplier.multiply(paramECPoint2, paramBigInteger2);
      return eCPoint1.add(eCPoint2);
    } 
    int m = j;
    int n = (i + m - 1) / m;
    ECPoint eCPoint = eCCurve.getInfinity();
    int i1 = n * m;
    int[] arrayOfInt1 = Nat.fromBigInteger(i1, paramBigInteger1);
    int[] arrayOfInt2 = Nat.fromBigInteger(i1, paramBigInteger2);
    int i2 = i1 - 1;
    for (byte b = 0; b < n; b++) {
      int i3 = 0, i4 = 0;
      int i5;
      for (i5 = i2 - b; i5 >= 0; i5 -= n) {
        int i6 = arrayOfInt1[i5 >>> 5] >>> (i5 & 0x1F);
        i3 ^= i6 >>> 1;
        i3 <<= 1;
        i3 ^= i6;
        int i7 = arrayOfInt2[i5 >>> 5] >>> (i5 & 0x1F);
        i4 ^= i7 >>> 1;
        i4 <<= 1;
        i4 ^= i7;
      } 
      ECPoint eCPoint1 = eCLookupTable1.lookupVar(i3);
      ECPoint eCPoint2 = eCLookupTable2.lookupVar(i4);
      ECPoint eCPoint3 = eCPoint1.add(eCPoint2);
      eCPoint = eCPoint.twicePlus(eCPoint3);
    } 
    return eCPoint.add(fixedPointPreCompInfo1.getOffset()).add(fixedPointPreCompInfo2.getOffset());
  }
}
