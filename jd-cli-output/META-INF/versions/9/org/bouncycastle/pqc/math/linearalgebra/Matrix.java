package META-INF.versions.9.org.bouncycastle.pqc.math.linearalgebra;

import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.Vector;

public abstract class Matrix {
  protected int numRows;
  
  protected int numColumns;
  
  public static final char MATRIX_TYPE_ZERO = 'Z';
  
  public static final char MATRIX_TYPE_UNIT = 'I';
  
  public static final char MATRIX_TYPE_RANDOM_LT = 'L';
  
  public static final char MATRIX_TYPE_RANDOM_UT = 'U';
  
  public static final char MATRIX_TYPE_RANDOM_REGULAR = 'R';
  
  public int getNumRows() {
    return this.numRows;
  }
  
  public int getNumColumns() {
    return this.numColumns;
  }
  
  public abstract byte[] getEncoded();
  
  public abstract org.bouncycastle.pqc.math.linearalgebra.Matrix computeInverse();
  
  public abstract boolean isZero();
  
  public abstract org.bouncycastle.pqc.math.linearalgebra.Matrix rightMultiply(org.bouncycastle.pqc.math.linearalgebra.Matrix paramMatrix);
  
  public abstract org.bouncycastle.pqc.math.linearalgebra.Matrix rightMultiply(Permutation paramPermutation);
  
  public abstract Vector leftMultiply(Vector paramVector);
  
  public abstract Vector rightMultiply(Vector paramVector);
  
  public abstract String toString();
}
