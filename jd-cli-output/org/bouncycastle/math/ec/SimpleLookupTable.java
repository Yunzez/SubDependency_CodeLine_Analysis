package org.bouncycastle.math.ec;

public class SimpleLookupTable extends AbstractECLookupTable {
  private final ECPoint[] points;
  
  private static ECPoint[] copy(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2) {
    ECPoint[] arrayOfECPoint = new ECPoint[paramInt2];
    for (byte b = 0; b < paramInt2; b++)
      arrayOfECPoint[b] = paramArrayOfECPoint[paramInt1 + b]; 
    return arrayOfECPoint;
  }
  
  public SimpleLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2) {
    this.points = copy(paramArrayOfECPoint, paramInt1, paramInt2);
  }
  
  public int getSize() {
    return this.points.length;
  }
  
  public ECPoint lookup(int paramInt) {
    throw new UnsupportedOperationException("Constant-time lookup not supported");
  }
  
  public ECPoint lookupVar(int paramInt) {
    return this.points[paramInt];
  }
}
