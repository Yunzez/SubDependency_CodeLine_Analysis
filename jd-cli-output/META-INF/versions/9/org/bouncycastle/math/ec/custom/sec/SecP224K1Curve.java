package META-INF.versions.9.org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP224K1Field;
import org.bouncycastle.math.ec.custom.sec.SecP224K1FieldElement;
import org.bouncycastle.math.ec.custom.sec.SecP224K1Point;
import org.bouncycastle.math.raw.Nat224;
import org.bouncycastle.util.encoders.Hex;

public class SecP224K1Curve extends ECCurve.AbstractFp {
  public static final BigInteger q = SecP224K1FieldElement.Q;
  
  private static final int SECP224K1_DEFAULT_COORDS = 2;
  
  private static final ECFieldElement[] SECP224K1_AFFINE_ZS = new ECFieldElement[] { new SecP224K1FieldElement(ECConstants.ONE) };
  
  protected SecP224K1Point infinity;
  
  public SecP224K1Curve() {
    super(q);
    this.infinity = new SecP224K1Point(this, null, null);
    this.a = fromBigInteger(ECConstants.ZERO);
    this.b = fromBigInteger(BigInteger.valueOf(5L));
    this.order = new BigInteger(1, Hex.decodeStrict("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"));
    this.cofactor = BigInteger.valueOf(1L);
    this.coord = 2;
  }
  
  protected ECCurve cloneCurve() {
    return new org.bouncycastle.math.ec.custom.sec.SecP224K1Curve();
  }
  
  public boolean supportsCoordinateSystem(int paramInt) {
    switch (paramInt) {
      case 2:
        return true;
    } 
    return false;
  }
  
  public BigInteger getQ() {
    return q;
  }
  
  public int getFieldSize() {
    return q.bitLength();
  }
  
  public ECFieldElement fromBigInteger(BigInteger paramBigInteger) {
    return new SecP224K1FieldElement(paramBigInteger);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    return new SecP224K1Point(this, paramECFieldElement1, paramECFieldElement2);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    return new SecP224K1Point(this, paramECFieldElement1, paramECFieldElement2, paramArrayOfECFieldElement);
  }
  
  public ECPoint getInfinity() {
    return this.infinity;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2) {
    int[] arrayOfInt = new int[paramInt2 * 7 * 2];
    boolean bool = false;
    for (byte b = 0; b < paramInt2; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      Nat224.copy(((SecP224K1FieldElement)eCPoint.getRawXCoord()).x, 0, arrayOfInt, bool);
      bool += true;
      Nat224.copy(((SecP224K1FieldElement)eCPoint.getRawYCoord()).x, 0, arrayOfInt, bool);
      bool += true;
    } 
    return (ECLookupTable)new Object(this, paramInt2, arrayOfInt);
  }
  
  public ECFieldElement randomFieldElement(SecureRandom paramSecureRandom) {
    int[] arrayOfInt = Nat224.create();
    SecP224K1Field.random(paramSecureRandom, arrayOfInt);
    return new SecP224K1FieldElement(arrayOfInt);
  }
  
  public ECFieldElement randomFieldElementMult(SecureRandom paramSecureRandom) {
    int[] arrayOfInt = Nat224.create();
    SecP224K1Field.randomMult(paramSecureRandom, arrayOfInt);
    return new SecP224K1FieldElement(arrayOfInt);
  }
}
