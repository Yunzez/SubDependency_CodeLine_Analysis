package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat160;

public class SecP160R2Curve extends ECCurve.AbstractFp {
  public static final BigInteger q = SecP160R2FieldElement.Q;
  
  private static final int SECP160R2_DEFAULT_COORDS = 2;
  
  private static final ECFieldElement[] SECP160R2_AFFINE_ZS = new ECFieldElement[] { new SecP160R2FieldElement(ECConstants.ONE) };
  
  protected SecP160R2Point infinity = new SecP160R2Point(this, null, null);
  
  public SecP160R2Curve() {
    super(q);
  }
  
  protected ECCurve cloneCurve() {
    return new SecP160R2Curve();
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
    return new SecP160R2FieldElement(paramBigInteger);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    return new SecP160R2Point(this, paramECFieldElement1, paramECFieldElement2);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    return new SecP160R2Point(this, paramECFieldElement1, paramECFieldElement2, paramArrayOfECFieldElement);
  }
  
  public ECPoint getInfinity() {
    return this.infinity;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, final int len) {
    final int[] table = new int[len * 5 * 2];
    boolean bool = false;
    for (byte b = 0; b < len; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      Nat160.copy(((SecP160R2FieldElement)eCPoint.getRawXCoord()).x, 0, arrayOfInt, bool);
      bool += true;
      Nat160.copy(((SecP160R2FieldElement)eCPoint.getRawYCoord()).x, 0, arrayOfInt, bool);
      bool += true;
    } 
    return new AbstractECLookupTable() {
        public int getSize() {
          return len;
        }
        
        public ECPoint lookup(int param1Int) {
          int[] arrayOfInt1 = Nat160.create();
          int[] arrayOfInt2 = Nat160.create();
          byte b1 = 0;
          for (byte b2 = 0; b2 < len; b2++) {
            int i = (b2 ^ param1Int) - 1 >> 31;
            for (byte b = 0; b < 5; b++) {
              arrayOfInt1[b] = arrayOfInt1[b] ^ table[b1 + b] & i;
              arrayOfInt2[b] = arrayOfInt2[b] ^ table[b1 + 5 + b] & i;
            } 
            b1 += 10;
          } 
          return createPoint(arrayOfInt1, arrayOfInt2);
        }
        
        public ECPoint lookupVar(int param1Int) {
          int[] arrayOfInt1 = Nat160.create();
          int[] arrayOfInt2 = Nat160.create();
          int i = param1Int * 5 * 2;
          for (byte b = 0; b < 5; b++) {
            arrayOfInt1[b] = table[i + b];
            arrayOfInt2[b] = table[i + 5 + b];
          } 
          return createPoint(arrayOfInt1, arrayOfInt2);
        }
        
        private ECPoint createPoint(int[] param1ArrayOfint1, int[] param1ArrayOfint2) {
          return SecP160R2Curve.this.createRawPoint(new SecP160R2FieldElement(param1ArrayOfint1), new SecP160R2FieldElement(param1ArrayOfint2), SecP160R2Curve.SECP160R2_AFFINE_ZS);
        }
      };
  }
  
  public ECFieldElement randomFieldElement(SecureRandom paramSecureRandom) {
    int[] arrayOfInt = Nat160.create();
    SecP160R2Field.random(paramSecureRandom, arrayOfInt);
    return new SecP160R2FieldElement(arrayOfInt);
  }
  
  public ECFieldElement randomFieldElementMult(SecureRandom paramSecureRandom) {
    int[] arrayOfInt = Nat160.create();
    SecP160R2Field.randomMult(paramSecureRandom, arrayOfInt);
    return new SecP160R2FieldElement(arrayOfInt);
  }
}
