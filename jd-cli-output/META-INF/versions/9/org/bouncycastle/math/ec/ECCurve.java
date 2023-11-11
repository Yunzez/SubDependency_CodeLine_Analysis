package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.GLVMultiplier;
import org.bouncycastle.math.ec.PreCompCallback;
import org.bouncycastle.math.ec.PreCompInfo;
import org.bouncycastle.math.ec.WNafL2RMultiplier;
import org.bouncycastle.math.ec.endo.ECEndomorphism;
import org.bouncycastle.math.ec.endo.GLVEndomorphism;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

public abstract class ECCurve {
  public static final int COORD_AFFINE = 0;
  
  public static final int COORD_HOMOGENEOUS = 1;
  
  public static final int COORD_JACOBIAN = 2;
  
  public static final int COORD_JACOBIAN_CHUDNOVSKY = 3;
  
  public static final int COORD_JACOBIAN_MODIFIED = 4;
  
  public static final int COORD_LAMBDA_AFFINE = 5;
  
  public static final int COORD_LAMBDA_PROJECTIVE = 6;
  
  public static final int COORD_SKEWED = 7;
  
  protected FiniteField field;
  
  protected ECFieldElement a;
  
  protected ECFieldElement b;
  
  protected BigInteger order;
  
  protected BigInteger cofactor;
  
  public static int[] getAllCoordinateSystems() {
    return new int[] { 0, 1, 2, 3, 4, 5, 6, 7 };
  }
  
  protected int coord = 0;
  
  protected ECEndomorphism endomorphism = null;
  
  protected ECMultiplier multiplier = null;
  
  protected ECCurve(FiniteField paramFiniteField) {
    this.field = paramFiniteField;
  }
  
  public abstract int getFieldSize();
  
  public abstract ECFieldElement fromBigInteger(BigInteger paramBigInteger);
  
  public abstract boolean isValidFieldElement(BigInteger paramBigInteger);
  
  public abstract ECFieldElement randomFieldElement(SecureRandom paramSecureRandom);
  
  public abstract ECFieldElement randomFieldElementMult(SecureRandom paramSecureRandom);
  
  public synchronized Config configure() {
    return new Config(this, this.coord, this.endomorphism, this.multiplier);
  }
  
  public ECPoint validatePoint(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    ECPoint eCPoint = createPoint(paramBigInteger1, paramBigInteger2);
    if (!eCPoint.isValid())
      throw new IllegalArgumentException("Invalid point coordinates"); 
    return eCPoint;
  }
  
  public ECPoint createPoint(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    return createRawPoint(fromBigInteger(paramBigInteger1), fromBigInteger(paramBigInteger2));
  }
  
  protected abstract org.bouncycastle.math.ec.ECCurve cloneCurve();
  
  protected abstract ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2);
  
  protected abstract ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement);
  
  protected ECMultiplier createDefaultMultiplier() {
    if (this.endomorphism instanceof GLVEndomorphism)
      return new GLVMultiplier(this, (GLVEndomorphism)this.endomorphism); 
    return new WNafL2RMultiplier();
  }
  
  public boolean supportsCoordinateSystem(int paramInt) {
    return (paramInt == 0);
  }
  
  public PreCompInfo getPreCompInfo(ECPoint paramECPoint, String paramString) {
    Hashtable hashtable;
    checkPoint(paramECPoint);
    synchronized (paramECPoint) {
      hashtable = paramECPoint.preCompTable;
    } 
    if (null == hashtable)
      return null; 
    synchronized (hashtable) {
      return (PreCompInfo)hashtable.get(paramString);
    } 
  }
  
  public PreCompInfo precompute(ECPoint paramECPoint, String paramString, PreCompCallback paramPreCompCallback) {
    Hashtable<Object, Object> hashtable;
    checkPoint(paramECPoint);
    synchronized (paramECPoint) {
      hashtable = paramECPoint.preCompTable;
      if (null == hashtable)
        paramECPoint.preCompTable = hashtable = new Hashtable<>(4); 
    } 
    synchronized (hashtable) {
      PreCompInfo preCompInfo1 = (PreCompInfo)hashtable.get(paramString);
      PreCompInfo preCompInfo2 = paramPreCompCallback.precompute(preCompInfo1);
      if (preCompInfo2 != preCompInfo1)
        hashtable.put(paramString, preCompInfo2); 
      return preCompInfo2;
    } 
  }
  
  public ECPoint importPoint(ECPoint paramECPoint) {
    if (this == paramECPoint.getCurve())
      return paramECPoint; 
    if (paramECPoint.isInfinity())
      return getInfinity(); 
    paramECPoint = paramECPoint.normalize();
    return createPoint(paramECPoint.getXCoord().toBigInteger(), paramECPoint.getYCoord().toBigInteger());
  }
  
  public void normalizeAll(ECPoint[] paramArrayOfECPoint) {
    normalizeAll(paramArrayOfECPoint, 0, paramArrayOfECPoint.length, null);
  }
  
  public void normalizeAll(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2, ECFieldElement paramECFieldElement) {
    checkPoints(paramArrayOfECPoint, paramInt1, paramInt2);
    switch (getCoordinateSystem()) {
      case 0:
      case 5:
        if (paramECFieldElement != null)
          throw new IllegalArgumentException("'iso' not valid for affine coordinates"); 
        return;
    } 
    ECFieldElement[] arrayOfECFieldElement = new ECFieldElement[paramInt2];
    int[] arrayOfInt = new int[paramInt2];
    byte b1 = 0;
    byte b2;
    for (b2 = 0; b2 < paramInt2; b2++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b2];
      if (null != eCPoint && (paramECFieldElement != null || !eCPoint.isNormalized())) {
        arrayOfECFieldElement[b1] = eCPoint.getZCoord(0);
        arrayOfInt[b1++] = paramInt1 + b2;
      } 
    } 
    if (b1 == 0)
      return; 
    ECAlgorithms.montgomeryTrick(arrayOfECFieldElement, 0, b1, paramECFieldElement);
    for (b2 = 0; b2 < b1; b2++) {
      int i = arrayOfInt[b2];
      paramArrayOfECPoint[i] = paramArrayOfECPoint[i].normalize(arrayOfECFieldElement[b2]);
    } 
  }
  
  public abstract ECPoint getInfinity();
  
  public FiniteField getField() {
    return this.field;
  }
  
  public ECFieldElement getA() {
    return this.a;
  }
  
  public ECFieldElement getB() {
    return this.b;
  }
  
  public BigInteger getOrder() {
    return this.order;
  }
  
  public BigInteger getCofactor() {
    return this.cofactor;
  }
  
  public int getCoordinateSystem() {
    return this.coord;
  }
  
  protected abstract ECPoint decompressPoint(int paramInt, BigInteger paramBigInteger);
  
  public ECEndomorphism getEndomorphism() {
    return this.endomorphism;
  }
  
  public ECMultiplier getMultiplier() {
    if (this.multiplier == null)
      this.multiplier = createDefaultMultiplier(); 
    return this.multiplier;
  }
  
  public ECPoint decodePoint(byte[] paramArrayOfbyte) {
    int j;
    BigInteger bigInteger1, bigInteger2;
    ECPoint eCPoint = null;
    int i = (getFieldSize() + 7) / 8;
    byte b = paramArrayOfbyte[0];
    switch (b) {
      case 0:
        if (paramArrayOfbyte.length != 1)
          throw new IllegalArgumentException("Incorrect length for infinity encoding"); 
        eCPoint = getInfinity();
        break;
      case 2:
      case 3:
        if (paramArrayOfbyte.length != i + 1)
          throw new IllegalArgumentException("Incorrect length for compressed encoding"); 
        j = b & 0x1;
        bigInteger2 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1, i);
        eCPoint = decompressPoint(j, bigInteger2);
        if (!eCPoint.implIsValid(true, true))
          throw new IllegalArgumentException("Invalid point"); 
        break;
      case 4:
        if (paramArrayOfbyte.length != 2 * i + 1)
          throw new IllegalArgumentException("Incorrect length for uncompressed encoding"); 
        bigInteger1 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1, i);
        bigInteger2 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1 + i, i);
        eCPoint = validatePoint(bigInteger1, bigInteger2);
        break;
      case 6:
      case 7:
        if (paramArrayOfbyte.length != 2 * i + 1)
          throw new IllegalArgumentException("Incorrect length for hybrid encoding"); 
        bigInteger1 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1, i);
        bigInteger2 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1 + i, i);
        if (bigInteger2.testBit(0) != ((b == 7)))
          throw new IllegalArgumentException("Inconsistent Y coordinate in hybrid encoding"); 
        eCPoint = validatePoint(bigInteger1, bigInteger2);
        break;
      default:
        throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(b, 16));
    } 
    if (b != 0 && eCPoint.isInfinity())
      throw new IllegalArgumentException("Invalid infinity encoding"); 
    return eCPoint;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2) {
    int i = getFieldSize() + 7 >>> 3;
    byte[] arrayOfByte = new byte[paramInt2 * i * 2];
    int j = 0;
    for (byte b = 0; b < paramInt2; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      byte[] arrayOfByte1 = eCPoint.getRawXCoord().toBigInteger().toByteArray();
      byte[] arrayOfByte2 = eCPoint.getRawYCoord().toBigInteger().toByteArray();
      byte b1 = (arrayOfByte1.length > i) ? 1 : 0;
      int k = arrayOfByte1.length - b1;
      byte b2 = (arrayOfByte2.length > i) ? 1 : 0;
      int m = arrayOfByte2.length - b2;
      System.arraycopy(arrayOfByte1, b1, arrayOfByte, j + i - k, k);
      j += i;
      System.arraycopy(arrayOfByte2, b2, arrayOfByte, j + i - m, m);
      j += i;
    } 
    return (ECLookupTable)new Object(this, paramInt2, i, arrayOfByte);
  }
  
  protected void checkPoint(ECPoint paramECPoint) {
    if (null == paramECPoint || this != paramECPoint.getCurve())
      throw new IllegalArgumentException("'point' must be non-null and on this curve"); 
  }
  
  protected void checkPoints(ECPoint[] paramArrayOfECPoint) {
    checkPoints(paramArrayOfECPoint, 0, paramArrayOfECPoint.length);
  }
  
  protected void checkPoints(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2) {
    if (paramArrayOfECPoint == null)
      throw new IllegalArgumentException("'points' cannot be null"); 
    if (paramInt1 < 0 || paramInt2 < 0 || paramInt1 > paramArrayOfECPoint.length - paramInt2)
      throw new IllegalArgumentException("invalid range specified for 'points'"); 
    for (byte b = 0; b < paramInt2; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      if (null != eCPoint && this != eCPoint.getCurve())
        throw new IllegalArgumentException("'points' entries must be null or on this curve"); 
    } 
  }
  
  public boolean equals(org.bouncycastle.math.ec.ECCurve paramECCurve) {
    return (this == paramECCurve || (null != paramECCurve && 
      
      getField().equals(paramECCurve.getField()) && 
      getA().toBigInteger().equals(paramECCurve.getA().toBigInteger()) && 
      getB().toBigInteger().equals(paramECCurve.getB().toBigInteger())));
  }
  
  public boolean equals(Object paramObject) {
    return (this == paramObject || (paramObject instanceof org.bouncycastle.math.ec.ECCurve && equals((org.bouncycastle.math.ec.ECCurve)paramObject)));
  }
  
  public int hashCode() {
    return getField().hashCode() ^ 
      Integers.rotateLeft(getA().toBigInteger().hashCode(), 8) ^ 
      Integers.rotateLeft(getB().toBigInteger().hashCode(), 16);
  }
}
