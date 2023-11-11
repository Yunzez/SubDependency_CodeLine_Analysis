package META-INF.versions.9.org.bouncycastle.math.ec.endo;

import java.math.BigInteger;

public class ScalarSplitParameters {
  protected final BigInteger v1A;
  
  protected final BigInteger v1B;
  
  protected final BigInteger v2A;
  
  protected final BigInteger v2B;
  
  protected final BigInteger g1;
  
  protected final BigInteger g2;
  
  protected final int bits;
  
  private static void checkVector(BigInteger[] paramArrayOfBigInteger, String paramString) {
    if (paramArrayOfBigInteger == null || paramArrayOfBigInteger.length != 2 || paramArrayOfBigInteger[0] == null || paramArrayOfBigInteger[1] == null)
      throw new IllegalArgumentException("'" + paramString + "' must consist of exactly 2 (non-null) values"); 
  }
  
  public ScalarSplitParameters(BigInteger[] paramArrayOfBigInteger1, BigInteger[] paramArrayOfBigInteger2, BigInteger paramBigInteger1, BigInteger paramBigInteger2, int paramInt) {
    checkVector(paramArrayOfBigInteger1, "v1");
    checkVector(paramArrayOfBigInteger2, "v2");
    this.v1A = paramArrayOfBigInteger1[0];
    this.v1B = paramArrayOfBigInteger1[1];
    this.v2A = paramArrayOfBigInteger2[0];
    this.v2B = paramArrayOfBigInteger2[1];
    this.g1 = paramBigInteger1;
    this.g2 = paramBigInteger2;
    this.bits = paramInt;
  }
  
  public BigInteger getV1A() {
    return this.v1A;
  }
  
  public BigInteger getV1B() {
    return this.v1B;
  }
  
  public BigInteger getV2A() {
    return this.v2A;
  }
  
  public BigInteger getV2B() {
    return this.v2B;
  }
  
  public BigInteger getG1() {
    return this.g1;
  }
  
  public BigInteger getG2() {
    return this.g2;
  }
  
  public int getBits() {
    return this.bits;
  }
}
