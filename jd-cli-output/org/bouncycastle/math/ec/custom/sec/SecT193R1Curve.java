package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.AbstractECLookupTable;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECLookupTable;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.raw.Nat256;

public class SecT193R1Curve extends ECCurve.AbstractF2m {
  private static final int SECT193R1_DEFAULT_COORDS = 6;
  
  private static final ECFieldElement[] SECT193R1_AFFINE_ZS = new ECFieldElement[] { new SecT193FieldElement(ECConstants.ONE) };
  
  protected SecT193R1Point infinity = new SecT193R1Point(this, null, null);
  
  public SecT193R1Curve() {
    super(193, 15, 0, 0);
  }
  
  protected ECCurve cloneCurve() {
    return new SecT193R1Curve();
  }
  
  public boolean supportsCoordinateSystem(int paramInt) {
    switch (paramInt) {
      case 6:
        return true;
    } 
    return false;
  }
  
  public int getFieldSize() {
    return 193;
  }
  
  public ECFieldElement fromBigInteger(BigInteger paramBigInteger) {
    return new SecT193FieldElement(paramBigInteger);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2) {
    return new SecT193R1Point(this, paramECFieldElement1, paramECFieldElement2);
  }
  
  protected ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement) {
    return new SecT193R1Point(this, paramECFieldElement1, paramECFieldElement2, paramArrayOfECFieldElement);
  }
  
  public ECPoint getInfinity() {
    return this.infinity;
  }
  
  public boolean isKoblitz() {
    return false;
  }
  
  public int getM() {
    return 193;
  }
  
  public boolean isTrinomial() {
    return true;
  }
  
  public int getK1() {
    return 15;
  }
  
  public int getK2() {
    return 0;
  }
  
  public int getK3() {
    return 0;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, final int len) {
    final long[] table = new long[len * 4 * 2];
    boolean bool = false;
    for (byte b = 0; b < len; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      Nat256.copy64(((SecT193FieldElement)eCPoint.getRawXCoord()).x, 0, arrayOfLong, bool);
      bool += true;
      Nat256.copy64(((SecT193FieldElement)eCPoint.getRawYCoord()).x, 0, arrayOfLong, bool);
      bool += true;
    } 
    return new AbstractECLookupTable() {
        public int getSize() {
          return len;
        }
        
        public ECPoint lookup(int param1Int) {
          long[] arrayOfLong1 = Nat256.create64();
          long[] arrayOfLong2 = Nat256.create64();
          byte b1 = 0;
          for (byte b2 = 0; b2 < len; b2++) {
            long l = ((b2 ^ param1Int) - 1 >> 31);
            for (byte b = 0; b < 4; b++) {
              arrayOfLong1[b] = arrayOfLong1[b] ^ table[b1 + b] & l;
              arrayOfLong2[b] = arrayOfLong2[b] ^ table[b1 + 4 + b] & l;
            } 
            b1 += 8;
          } 
          return createPoint(arrayOfLong1, arrayOfLong2);
        }
        
        public ECPoint lookupVar(int param1Int) {
          long[] arrayOfLong1 = Nat256.create64();
          long[] arrayOfLong2 = Nat256.create64();
          int i = param1Int * 4 * 2;
          for (byte b = 0; b < 4; b++) {
            arrayOfLong1[b] = table[i + b];
            arrayOfLong2[b] = table[i + 4 + b];
          } 
          return createPoint(arrayOfLong1, arrayOfLong2);
        }
        
        private ECPoint createPoint(long[] param1ArrayOflong1, long[] param1ArrayOflong2) {
          return SecT193R1Curve.this.createRawPoint(new SecT193FieldElement(param1ArrayOflong1), new SecT193FieldElement(param1ArrayOflong2), SecT193R1Curve.SECT193R1_AFFINE_ZS);
        }
      };
  }
}
