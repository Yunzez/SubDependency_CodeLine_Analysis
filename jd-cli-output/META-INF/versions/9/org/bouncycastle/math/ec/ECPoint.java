package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.PreCompCallback;
import org.bouncycastle.math.ec.ValidityPrecompInfo;

public abstract class ECPoint {
  protected static final ECFieldElement[] EMPTY_ZS = new ECFieldElement[0];
  
  protected ECCurve curve;
  
  protected ECFieldElement x;
  
  protected ECFieldElement y;
  
  protected ECFieldElement[] zs;
  
  protected static ECFieldElement[] getInitialZCoords(ECCurve paramECCurve) {
    boolean bool = (null == paramECCurve) ? false : paramECCurve.getCoordinateSystem();
    switch (bool) {
      case false:
      case true:
        return EMPTY_ZS;
    } 
    ECFieldElement eCFieldElement = paramECCurve.fromBigInteger(ECConstants.ONE);
    switch (bool) {
      case true:
      case true:
      case true:
        return new ECFieldElement[] { eCFieldElement };
      case true:
        return new ECFieldElement[] { eCFieldElement, eCFieldElement, eCFieldElement };
      case true:
        return new ECFieldElement[] { eCFieldElement, paramECCurve.getA() };
    } 
    throw new IllegalArgumentException("unknown coordinate system");
  }
  
  protected Hashtable preCompTable = null;
  
  protected ECPoint(ECCurve paramECCurve, ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    this(paramECCurve, paramECFieldElement1, paramECFieldElement2, getInitialZCoords(paramECCurve));
  }
  
  protected ECPoint(ECCurve paramECCurve, ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    this.curve = paramECCurve;
    this.x = paramECFieldElement1;
    this.y = paramECFieldElement2;
    this.zs = paramArrayOfECFieldElement;
  }
  
  protected abstract boolean satisfiesCurveEquation();
  
  protected boolean satisfiesOrder() {
    if (ECConstants.ONE.equals(this.curve.getCofactor()))
      return true; 
    BigInteger bigInteger = this.curve.getOrder();
    return (bigInteger == null || ECAlgorithms.referenceMultiply(this, bigInteger).isInfinity());
  }
  
  public final org.bouncycastle.math.ec.ECPoint getDetachedPoint() {
    return normalize().detach();
  }
  
  public ECCurve getCurve() {
    return this.curve;
  }
  
  protected abstract org.bouncycastle.math.ec.ECPoint detach();
  
  protected int getCurveCoordinateSystem() {
    return (null == this.curve) ? 0 : this.curve.getCoordinateSystem();
  }
  
  public ECFieldElement getAffineXCoord() {
    checkNormalized();
    return getXCoord();
  }
  
  public ECFieldElement getAffineYCoord() {
    checkNormalized();
    return getYCoord();
  }
  
  public ECFieldElement getXCoord() {
    return this.x;
  }
  
  public ECFieldElement getYCoord() {
    return this.y;
  }
  
  public ECFieldElement getZCoord(int paramInt) {
    return (paramInt < 0 || paramInt >= this.zs.length) ? null : this.zs[paramInt];
  }
  
  public ECFieldElement[] getZCoords() {
    int i = this.zs.length;
    if (i == 0)
      return EMPTY_ZS; 
    ECFieldElement[] arrayOfECFieldElement = new ECFieldElement[i];
    System.arraycopy(this.zs, 0, arrayOfECFieldElement, 0, i);
    return arrayOfECFieldElement;
  }
  
  public final ECFieldElement getRawXCoord() {
    return this.x;
  }
  
  public final ECFieldElement getRawYCoord() {
    return this.y;
  }
  
  protected final ECFieldElement[] getRawZCoords() {
    return this.zs;
  }
  
  protected void checkNormalized() {
    if (!isNormalized())
      throw new IllegalStateException("point not in normal form"); 
  }
  
  public boolean isNormalized() {
    int i = getCurveCoordinateSystem();
    return (i == 0 || i == 5 || 
      
      isInfinity() || this.zs[0]
      .isOne());
  }
  
  public org.bouncycastle.math.ec.ECPoint normalize() {
    if (isInfinity())
      return this; 
    switch (getCurveCoordinateSystem()) {
      case 0:
      case 5:
        return this;
    } 
    ECFieldElement eCFieldElement1 = getZCoord(0);
    if (eCFieldElement1.isOne())
      return this; 
    if (null == this.curve)
      throw new IllegalStateException("Detached points must be in affine coordinates"); 
    SecureRandom secureRandom = CryptoServicesRegistrar.getSecureRandom();
    ECFieldElement eCFieldElement2 = this.curve.randomFieldElementMult(secureRandom);
    ECFieldElement eCFieldElement3 = eCFieldElement1.multiply(eCFieldElement2).invert().multiply(eCFieldElement2);
    return normalize(eCFieldElement3);
  }
  
  org.bouncycastle.math.ec.ECPoint normalize(ECFieldElement paramECFieldElement) {
    ECFieldElement eCFieldElement1;
    ECFieldElement eCFieldElement2;
    switch (getCurveCoordinateSystem()) {
      case 1:
      case 6:
        return createScaledPoint(paramECFieldElement, paramECFieldElement);
      case 2:
      case 3:
      case 4:
        eCFieldElement1 = paramECFieldElement.square();
        eCFieldElement2 = eCFieldElement1.multiply(paramECFieldElement);
        return createScaledPoint(eCFieldElement1, eCFieldElement2);
    } 
    throw new IllegalStateException("not a projective coordinate system");
  }
  
  protected org.bouncycastle.math.ec.ECPoint createScaledPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    return getCurve().createRawPoint(getRawXCoord().multiply(paramECFieldElement1), getRawYCoord().multiply(paramECFieldElement2));
  }
  
  public boolean isInfinity() {
    return (this.x == null || this.y == null || (this.zs.length > 0 && this.zs[0].isZero()));
  }
  
  public boolean isValid() {
    return implIsValid(false, true);
  }
  
  boolean isValidPartial() {
    return implIsValid(false, false);
  }
  
  boolean implIsValid(boolean paramBoolean1, boolean paramBoolean2) {
    if (isInfinity())
      return true; 
    ValidityPrecompInfo validityPrecompInfo = (ValidityPrecompInfo)getCurve().precompute(this, "bc_validity", (PreCompCallback)new Object(this, paramBoolean1, paramBoolean2));
    return !validityPrecompInfo.hasFailed();
  }
  
  public org.bouncycastle.math.ec.ECPoint scaleX(ECFieldElement paramECFieldElement) {
    return isInfinity() ? 
      this : 
      getCurve().createRawPoint(getRawXCoord().multiply(paramECFieldElement), getRawYCoord(), getRawZCoords());
  }
  
  public org.bouncycastle.math.ec.ECPoint scaleXNegateY(ECFieldElement paramECFieldElement) {
    return isInfinity() ? 
      this : 
      getCurve().createRawPoint(getRawXCoord().multiply(paramECFieldElement), getRawYCoord().negate(), getRawZCoords());
  }
  
  public org.bouncycastle.math.ec.ECPoint scaleY(ECFieldElement paramECFieldElement) {
    return isInfinity() ? 
      this : 
      getCurve().createRawPoint(getRawXCoord(), getRawYCoord().multiply(paramECFieldElement), getRawZCoords());
  }
  
  public org.bouncycastle.math.ec.ECPoint scaleYNegateX(ECFieldElement paramECFieldElement) {
    return isInfinity() ? 
      this : 
      getCurve().createRawPoint(getRawXCoord().negate(), getRawYCoord().multiply(paramECFieldElement), getRawZCoords());
  }
  
  public boolean equals(org.bouncycastle.math.ec.ECPoint paramECPoint) {
    if (null == paramECPoint)
      return false; 
    ECCurve eCCurve1 = getCurve(), eCCurve2 = paramECPoint.getCurve();
    boolean bool1 = (null == eCCurve1) ? true : false, bool2 = (null == eCCurve2) ? true : false;
    boolean bool3 = isInfinity(), bool4 = paramECPoint.isInfinity();
    if (bool3 || bool4)
      return (bool3 && bool4 && (bool1 || bool2 || eCCurve1.equals(eCCurve2))); 
    org.bouncycastle.math.ec.ECPoint eCPoint1 = this, eCPoint2 = paramECPoint;
    if (!bool1 || !bool2)
      if (bool1) {
        eCPoint2 = eCPoint2.normalize();
      } else if (bool2) {
        eCPoint1 = eCPoint1.normalize();
      } else {
        if (!eCCurve1.equals(eCCurve2))
          return false; 
        org.bouncycastle.math.ec.ECPoint[] arrayOfECPoint = { this, eCCurve1.importPoint(eCPoint2) };
        eCCurve1.normalizeAll(arrayOfECPoint);
        eCPoint1 = arrayOfECPoint[0];
        eCPoint2 = arrayOfECPoint[1];
      }  
    return (eCPoint1.getXCoord().equals(eCPoint2.getXCoord()) && eCPoint1.getYCoord().equals(eCPoint2.getYCoord()));
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (!(paramObject instanceof org.bouncycastle.math.ec.ECPoint))
      return false; 
    return equals((org.bouncycastle.math.ec.ECPoint)paramObject);
  }
  
  public int hashCode() {
    ECCurve eCCurve = getCurve();
    int i = (null == eCCurve) ? 0 : (eCCurve.hashCode() ^ 0xFFFFFFFF);
    if (!isInfinity()) {
      org.bouncycastle.math.ec.ECPoint eCPoint = normalize();
      i ^= eCPoint.getXCoord().hashCode() * 17;
      i ^= eCPoint.getYCoord().hashCode() * 257;
    } 
    return i;
  }
  
  public String toString() {
    if (isInfinity())
      return "INF"; 
    StringBuffer stringBuffer = new StringBuffer();
    stringBuffer.append('(');
    stringBuffer.append(getRawXCoord());
    stringBuffer.append(',');
    stringBuffer.append(getRawYCoord());
    for (byte b = 0; b < this.zs.length; b++) {
      stringBuffer.append(',');
      stringBuffer.append(this.zs[b]);
    } 
    stringBuffer.append(')');
    return stringBuffer.toString();
  }
  
  public byte[] getEncoded(boolean paramBoolean) {
    if (isInfinity())
      return new byte[1]; 
    org.bouncycastle.math.ec.ECPoint eCPoint = normalize();
    byte[] arrayOfByte1 = eCPoint.getXCoord().getEncoded();
    if (paramBoolean) {
      byte[] arrayOfByte = new byte[arrayOfByte1.length + 1];
      arrayOfByte[0] = (byte)(eCPoint.getCompressionYTilde() ? 3 : 2);
      System.arraycopy(arrayOfByte1, 0, arrayOfByte, 1, arrayOfByte1.length);
      return arrayOfByte;
    } 
    byte[] arrayOfByte2 = eCPoint.getYCoord().getEncoded();
    byte[] arrayOfByte3 = new byte[arrayOfByte1.length + arrayOfByte2.length + 1];
    arrayOfByte3[0] = 4;
    System.arraycopy(arrayOfByte1, 0, arrayOfByte3, 1, arrayOfByte1.length);
    System.arraycopy(arrayOfByte2, 0, arrayOfByte3, arrayOfByte1.length + 1, arrayOfByte2.length);
    return arrayOfByte3;
  }
  
  protected abstract boolean getCompressionYTilde();
  
  public abstract org.bouncycastle.math.ec.ECPoint add(org.bouncycastle.math.ec.ECPoint paramECPoint);
  
  public abstract org.bouncycastle.math.ec.ECPoint negate();
  
  public abstract org.bouncycastle.math.ec.ECPoint subtract(org.bouncycastle.math.ec.ECPoint paramECPoint);
  
  public org.bouncycastle.math.ec.ECPoint timesPow2(int paramInt) {
    if (paramInt < 0)
      throw new IllegalArgumentException("'e' cannot be negative"); 
    org.bouncycastle.math.ec.ECPoint eCPoint = this;
    while (--paramInt >= 0)
      eCPoint = eCPoint.twice(); 
    return eCPoint;
  }
  
  public abstract org.bouncycastle.math.ec.ECPoint twice();
  
  public org.bouncycastle.math.ec.ECPoint twicePlus(org.bouncycastle.math.ec.ECPoint paramECPoint) {
    return twice().add(paramECPoint);
  }
  
  public org.bouncycastle.math.ec.ECPoint threeTimes() {
    return twicePlus(this);
  }
  
  public org.bouncycastle.math.ec.ECPoint multiply(BigInteger paramBigInteger) {
    return getCurve().getMultiplier().multiply(this, paramBigInteger);
  }
}
