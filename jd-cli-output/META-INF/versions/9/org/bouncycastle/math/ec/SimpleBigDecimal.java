package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECConstants;

class SimpleBigDecimal {
  private static final long serialVersionUID = 1L;
  
  private final BigInteger bigInt;
  
  private final int scale;
  
  public static org.bouncycastle.math.ec.SimpleBigDecimal getInstance(BigInteger paramBigInteger, int paramInt) {
    return new org.bouncycastle.math.ec.SimpleBigDecimal(paramBigInteger.shiftLeft(paramInt), paramInt);
  }
  
  public SimpleBigDecimal(BigInteger paramBigInteger, int paramInt) {
    if (paramInt < 0)
      throw new IllegalArgumentException("scale may not be negative"); 
    this.bigInt = paramBigInteger;
    this.scale = paramInt;
  }
  
  private void checkScale(org.bouncycastle.math.ec.SimpleBigDecimal paramSimpleBigDecimal) {
    if (this.scale != paramSimpleBigDecimal.scale)
      throw new IllegalArgumentException("Only SimpleBigDecimal of same scale allowed in arithmetic operations"); 
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal adjustScale(int paramInt) {
    if (paramInt < 0)
      throw new IllegalArgumentException("scale may not be negative"); 
    if (paramInt == this.scale)
      return this; 
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.shiftLeft(paramInt - this.scale), paramInt);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal add(org.bouncycastle.math.ec.SimpleBigDecimal paramSimpleBigDecimal) {
    checkScale(paramSimpleBigDecimal);
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.add(paramSimpleBigDecimal.bigInt), this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal add(BigInteger paramBigInteger) {
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.add(paramBigInteger.shiftLeft(this.scale)), this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal negate() {
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.negate(), this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal subtract(org.bouncycastle.math.ec.SimpleBigDecimal paramSimpleBigDecimal) {
    return add(paramSimpleBigDecimal.negate());
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal subtract(BigInteger paramBigInteger) {
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.subtract(paramBigInteger.shiftLeft(this.scale)), this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal multiply(org.bouncycastle.math.ec.SimpleBigDecimal paramSimpleBigDecimal) {
    checkScale(paramSimpleBigDecimal);
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.multiply(paramSimpleBigDecimal.bigInt), this.scale + this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal multiply(BigInteger paramBigInteger) {
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.multiply(paramBigInteger), this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal divide(org.bouncycastle.math.ec.SimpleBigDecimal paramSimpleBigDecimal) {
    checkScale(paramSimpleBigDecimal);
    BigInteger bigInteger = this.bigInt.shiftLeft(this.scale);
    return new org.bouncycastle.math.ec.SimpleBigDecimal(bigInteger.divide(paramSimpleBigDecimal.bigInt), this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal divide(BigInteger paramBigInteger) {
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.divide(paramBigInteger), this.scale);
  }
  
  public org.bouncycastle.math.ec.SimpleBigDecimal shiftLeft(int paramInt) {
    return new org.bouncycastle.math.ec.SimpleBigDecimal(this.bigInt.shiftLeft(paramInt), this.scale);
  }
  
  public int compareTo(org.bouncycastle.math.ec.SimpleBigDecimal paramSimpleBigDecimal) {
    checkScale(paramSimpleBigDecimal);
    return this.bigInt.compareTo(paramSimpleBigDecimal.bigInt);
  }
  
  public int compareTo(BigInteger paramBigInteger) {
    return this.bigInt.compareTo(paramBigInteger.shiftLeft(this.scale));
  }
  
  public BigInteger floor() {
    return this.bigInt.shiftRight(this.scale);
  }
  
  public BigInteger round() {
    org.bouncycastle.math.ec.SimpleBigDecimal simpleBigDecimal = new org.bouncycastle.math.ec.SimpleBigDecimal(ECConstants.ONE, 1);
    return add(simpleBigDecimal.adjustScale(this.scale)).floor();
  }
  
  public int intValue() {
    return floor().intValue();
  }
  
  public long longValue() {
    return floor().longValue();
  }
  
  public int getScale() {
    return this.scale;
  }
  
  public String toString() {
    if (this.scale == 0)
      return this.bigInt.toString(); 
    BigInteger bigInteger1 = floor();
    BigInteger bigInteger2 = this.bigInt.subtract(bigInteger1.shiftLeft(this.scale));
    if (this.bigInt.signum() == -1)
      bigInteger2 = ECConstants.ONE.shiftLeft(this.scale).subtract(bigInteger2); 
    if (bigInteger1.signum() == -1 && !bigInteger2.equals(ECConstants.ZERO))
      bigInteger1 = bigInteger1.add(ECConstants.ONE); 
    String str1 = bigInteger1.toString();
    char[] arrayOfChar = new char[this.scale];
    String str2 = bigInteger2.toString(2);
    int i = str2.length();
    int j = this.scale - i;
    byte b;
    for (b = 0; b < j; b++)
      arrayOfChar[b] = '0'; 
    for (b = 0; b < i; b++)
      arrayOfChar[j + b] = str2.charAt(b); 
    String str3 = new String(arrayOfChar);
    StringBuffer stringBuffer = new StringBuffer(str1);
    stringBuffer.append(".");
    stringBuffer.append(str3);
    return stringBuffer.toString();
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (!(paramObject instanceof org.bouncycastle.math.ec.SimpleBigDecimal))
      return false; 
    org.bouncycastle.math.ec.SimpleBigDecimal simpleBigDecimal = (org.bouncycastle.math.ec.SimpleBigDecimal)paramObject;
    return (this.bigInt.equals(simpleBigDecimal.bigInt) && this.scale == simpleBigDecimal.scale);
  }
  
  public int hashCode() {
    return this.bigInt.hashCode() ^ this.scale;
  }
}
