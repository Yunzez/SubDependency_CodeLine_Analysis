package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat128;

public class SecT113R1Curve extends ECCurve.AbstractF2m {
  private static final int SECT113R1_DEFAULT_COORDS = 6;
  
  private static final ECFieldElement[] SECT113R1_AFFINE_ZS = new ECFieldElement[] { new SecT113FieldElement(ECConstants.ONE) };
  
  protected SecT113R1Point infinity = new SecT113R1Point(this, null, null);
  
  public SecT113R1Curve() {
    super(113, 9, 0, 0);
  }
  
  protected ECCurve cloneCurve() {
    return new SecT113R1Curve();
  }
  
  public boolean supportsCoordinateSystem(int paramInt) {
    switch (paramInt) {
      case 6:
        return true;
    } 
    return false;
  }
  
  public int getFieldSize() {
    return 113;
  }
  
  public ECFieldElement fromBigInteger(BigInteger paramBigInteger) {
    return new SecT113FieldElement(paramBigInteger);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    return new SecT113R1Point(this, paramECFieldElement1, paramECFieldElement2);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    return new SecT113R1Point(this, paramECFieldElement1, paramECFieldElement2, paramArrayOfECFieldElement);
  }
  
  public ECPoint getInfinity() {
    return this.infinity;
  }
  
  public boolean isKoblitz() {
    return false;
  }
  
  public int getM() {
    return 113;
  }
  
  public boolean isTrinomial() {
    return true;
  }
  
  public int getK1() {
    return 9;
  }
  
  public int getK2() {
    return 0;
  }
  
  public int getK3() {
    return 0;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, final int len) {
    final long[] table = new long[len * 2 * 2];
    boolean bool = false;
    for (byte b = 0; b < len; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      Nat128.copy64(((SecT113FieldElement)eCPoint.getRawXCoord()).x, 0, arrayOfLong, bool);
      bool += true;
      Nat128.copy64(((SecT113FieldElement)eCPoint.getRawYCoord()).x, 0, arrayOfLong, bool);
      bool += true;
    } 
    return new AbstractECLookupTable() {
        public int getSize() {
          return len;
        }
        
        public ECPoint lookup(int param1Int) {
          long[] arrayOfLong1 = Nat128.create64();
          long[] arrayOfLong2 = Nat128.create64();
          byte b1 = 0;
          for (byte b2 = 0; b2 < len; b2++) {
            long l = ((b2 ^ param1Int) - 1 >> 31);
            for (byte b = 0; b < 2; b++) {
              arrayOfLong1[b] = arrayOfLong1[b] ^ table[b1 + b] & l;
              arrayOfLong2[b] = arrayOfLong2[b] ^ table[b1 + 2 + b] & l;
            } 
            b1 += 4;
          } 
          return createPoint(arrayOfLong1, arrayOfLong2);
        }
        
        public ECPoint lookupVar(int param1Int) {
          long[] arrayOfLong1 = Nat128.create64();
          long[] arrayOfLong2 = Nat128.create64();
          int i = param1Int * 2 * 2;
          for (byte b = 0; b < 2; b++) {
            arrayOfLong1[b] = table[i + b];
            arrayOfLong2[b] = table[i + 2 + b];
          } 
          return createPoint(arrayOfLong1, arrayOfLong2);
        }
        
        private ECPoint createPoint(long[] param1ArrayOflong1, long[] param1ArrayOflong2) {
          return SecT113R1Curve.this.createRawPoint(new SecT113FieldElement(param1ArrayOflong1), new SecT113FieldElement(param1ArrayOflong2), SecT113R1Curve.SECT113R1_AFFINE_ZS);
        }
      };
  }
}