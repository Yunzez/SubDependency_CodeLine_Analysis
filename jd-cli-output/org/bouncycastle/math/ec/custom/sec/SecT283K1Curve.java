package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.WTauNafMultiplier;
import org.bouncycastle.math.raw.Nat320;

public class SecT283K1Curve extends ECCurve.AbstractF2m {
  private static final int SECT283K1_DEFAULT_COORDS = 6;
  
  private static final ECFieldElement[] SECT283K1_AFFINE_ZS = new ECFieldElement[] { new SecT283FieldElement(ECConstants.ONE) };
  
  protected SecT283K1Point infinity = new SecT283K1Point(this, null, null);
  
  public SecT283K1Curve() {
    super(283, 5, 7, 12);
  }
  
  protected ECCurve cloneCurve() {
    return new SecT283K1Curve();
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
    return 283;
  }
  
  public ECFieldElement fromBigInteger(BigInteger paramBigInteger) {
    return new SecT283FieldElement(paramBigInteger);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    return new SecT283K1Point(this, paramECFieldElement1, paramECFieldElement2);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    return new SecT283K1Point(this, paramECFieldElement1, paramECFieldElement2, paramArrayOfECFieldElement);
  }
  
  public ECPoint getInfinity() {
    return this.infinity;
  }
  
  public boolean isKoblitz() {
    return true;
  }
  
  public int getM() {
    return 283;
  }
  
  public boolean isTrinomial() {
    return false;
  }
  
  public int getK1() {
    return 5;
  }
  
  public int getK2() {
    return 7;
  }
  
  public int getK3() {
    return 12;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, final int len) {
    final long[] table = new long[len * 5 * 2];
    boolean bool = false;
    for (byte b = 0; b < len; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      Nat320.copy64(((SecT283FieldElement)eCPoint.getRawXCoord()).x, 0, arrayOfLong, bool);
      bool += true;
      Nat320.copy64(((SecT283FieldElement)eCPoint.getRawYCoord()).x, 0, arrayOfLong, bool);
      bool += true;
    } 
    return new AbstractECLookupTable() {
        public int getSize() {
          return len;
        }
        
        public ECPoint lookup(int param1Int) {
          long[] arrayOfLong1 = Nat320.create64();
          long[] arrayOfLong2 = Nat320.create64();
          byte b1 = 0;
          for (byte b2 = 0; b2 < len; b2++) {
            long l = ((b2 ^ param1Int) - 1 >> 31);
            for (byte b = 0; b < 5; b++) {
              arrayOfLong1[b] = arrayOfLong1[b] ^ table[b1 + b] & l;
              arrayOfLong2[b] = arrayOfLong2[b] ^ table[b1 + 5 + b] & l;
            } 
            b1 += 10;
          } 
          return createPoint(arrayOfLong1, arrayOfLong2);
        }
        
        public ECPoint lookupVar(int param1Int) {
          long[] arrayOfLong1 = Nat320.create64();
          long[] arrayOfLong2 = Nat320.create64();
          int i = param1Int * 5 * 2;
          for (byte b = 0; b < 5; b++) {
            arrayOfLong1[b] = table[i + b];
            arrayOfLong2[b] = table[i + 5 + b];
          } 
          return createPoint(arrayOfLong1, arrayOfLong2);
        }
        
        private ECPoint createPoint(long[] param1ArrayOflong1, long[] param1ArrayOflong2) {
          return SecT283K1Curve.this.createRawPoint(new SecT283FieldElement(param1ArrayOflong1), new SecT283FieldElement(param1ArrayOflong2), SecT283K1Curve.SECT283K1_AFFINE_ZS);
        }
      };
  }
}
