package META-INF.versions.9.org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WTauNafMultiplier;
import org.bouncycastle.math.ec.custom.sec.SecT233FieldElement;
import org.bouncycastle.math.ec.custom.sec.SecT233K1Point;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.encoders.Hex;

public class SecT233K1Curve extends ECCurve.AbstractF2m {
  private static final int SECT233K1_DEFAULT_COORDS = 6;
  
  private static final ECFieldElement[] SECT233K1_AFFINE_ZS = new ECFieldElement[] { new SecT233FieldElement(ECConstants.ONE) };
  
  protected SecT233K1Point infinity;
  
  public SecT233K1Curve() {
    super(233, 74, 0, 0);
    this.infinity = new SecT233K1Point(this, null, null);
    this.a = fromBigInteger(BigInteger.valueOf(0L));
    this.b = fromBigInteger(BigInteger.valueOf(1L));
    this.order = new BigInteger(1, Hex.decodeStrict("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF"));
    this.cofactor = BigInteger.valueOf(4L);
    this.coord = 6;
  }
  
  protected ECCurve cloneCurve() {
    return new org.bouncycastle.math.ec.custom.sec.SecT233K1Curve();
  }
  
  public boolean supportsCoordinateSystem(int paramInt) {
    switch (paramInt) {
      case 6:
        return true;
    } 
    return false;
  }
  
  protected ECMultiplier createDefaultMultiplier() {
    return new WTauNafMultiplier();
  }
  
  public int getFieldSize() {
    return 233;
  }
  
  public ECFieldElement fromBigInteger(BigInteger paramBigInteger) {
    return new SecT233FieldElement(paramBigInteger);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    return new SecT233K1Point(this, paramECFieldElement1, paramECFieldElement2);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    return new SecT233K1Point(this, paramECFieldElement1, paramECFieldElement2, paramArrayOfECFieldElement);
  }
  
  public ECPoint getInfinity() {
    return this.infinity;
  }
  
  public boolean isKoblitz() {
    return true;
  }
  
  public int getM() {
    return 233;
  }
  
  public boolean isTrinomial() {
    return true;
  }
  
  public int getK1() {
    return 74;
  }
  
  public int getK2() {
    return 0;
  }
  
  public int getK3() {
    return 0;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2) {
    long[] arrayOfLong = new long[paramInt2 * 4 * 2];
    boolean bool = false;
    for (byte b = 0; b < paramInt2; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      Nat256.copy64(((SecT233FieldElement)eCPoint.getRawXCoord()).x, 0, arrayOfLong, bool);
      bool += true;
      Nat256.copy64(((SecT233FieldElement)eCPoint.getRawYCoord()).x, 0, arrayOfLong, bool);
      bool += true;
    } 
    return (ECLookupTable)new Object(this, paramInt2, arrayOfLong);
  }
}