package META-INF.versions.9.org.bouncycastle.pqc.math.linearalgebra;

import org.bouncycastle.pqc.math.linearalgebra.Permutation;

public abstract class Vector {
  protected int length;
  
  public final int getLength() {
    return this.length;
  }
  
  public abstract byte[] getEncoded();
  
  public abstract boolean isZero();
  
  public abstract org.bouncycastle.pqc.math.linearalgebra.Vector add(org.bouncycastle.pqc.math.linearalgebra.Vector paramVector);
  
  public abstract org.bouncycastle.pqc.math.linearalgebra.Vector multiply(Permutation paramPermutation);
  
  public abstract boolean equals(Object paramObject);
  
  public abstract int hashCode();
  
  public abstract String toString();
}
