package META-INF.versions.9.org.bouncycastle.math.field;

public interface Polynomial {
  int getDegree();
  
  int[] getExponentsPresent();
}
