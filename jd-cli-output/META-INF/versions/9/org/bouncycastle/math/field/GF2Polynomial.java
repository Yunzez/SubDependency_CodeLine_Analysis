package META-INF.versions.9.org.bouncycastle.math.field;

import org.bouncycastle.math.field.Polynomial;
import org.bouncycastle.util.Arrays;

class GF2Polynomial implements Polynomial {
  protected final int[] exponents;
  
  GF2Polynomial(int[] paramArrayOfint) {
    this.exponents = Arrays.clone(paramArrayOfint);
  }
  
  public int getDegree() {
    return this.exponents[this.exponents.length - 1];
  }
  
  public int[] getExponentsPresent() {
    return Arrays.clone(this.exponents);
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (!(paramObject instanceof org.bouncycastle.math.field.GF2Polynomial))
      return false; 
    org.bouncycastle.math.field.GF2Polynomial gF2Polynomial = (org.bouncycastle.math.field.GF2Polynomial)paramObject;
    return Arrays.areEqual(this.exponents, gF2Polynomial.exponents);
  }
  
  public int hashCode() {
    return Arrays.hashCode(this.exponents);
  }
}
