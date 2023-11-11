package META-INF.versions.9.org.bouncycastle.math.ec;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.util.BigIntegers;

public abstract class ECFieldElement implements ECConstants {
  public abstract BigInteger toBigInteger();
  
  public abstract String getFieldName();
  
  public abstract int getFieldSize();
  
  public abstract org.bouncycastle.math.ec.ECFieldElement add(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement);
  
  public abstract org.bouncycastle.math.ec.ECFieldElement addOne();
  
  public abstract org.bouncycastle.math.ec.ECFieldElement subtract(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement);
  
  public abstract org.bouncycastle.math.ec.ECFieldElement multiply(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement);
  
  public abstract org.bouncycastle.math.ec.ECFieldElement divide(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement);
  
  public abstract org.bouncycastle.math.ec.ECFieldElement negate();
  
  public abstract org.bouncycastle.math.ec.ECFieldElement square();
  
  public abstract org.bouncycastle.math.ec.ECFieldElement invert();
  
  public abstract org.bouncycastle.math.ec.ECFieldElement sqrt();
  
  public int bitLength() {
    return toBigInteger().bitLength();
  }
  
  public boolean isOne() {
    return (bitLength() == 1);
  }
  
  public boolean isZero() {
    return (0 == toBigInteger().signum());
  }
  
  public org.bouncycastle.math.ec.ECFieldElement multiplyMinusProduct(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement1, org.bouncycastle.math.ec.ECFieldElement paramECFieldElement2, org.bouncycastle.math.ec.ECFieldElement paramECFieldElement3) {
    return multiply(paramECFieldElement1).subtract(paramECFieldElement2.multiply(paramECFieldElement3));
  }
  
  public org.bouncycastle.math.ec.ECFieldElement multiplyPlusProduct(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement1, org.bouncycastle.math.ec.ECFieldElement paramECFieldElement2, org.bouncycastle.math.ec.ECFieldElement paramECFieldElement3) {
    return multiply(paramECFieldElement1).add(paramECFieldElement2.multiply(paramECFieldElement3));
  }
  
  public org.bouncycastle.math.ec.ECFieldElement squareMinusProduct(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement1, org.bouncycastle.math.ec.ECFieldElement paramECFieldElement2) {
    return square().subtract(paramECFieldElement1.multiply(paramECFieldElement2));
  }
  
  public org.bouncycastle.math.ec.ECFieldElement squarePlusProduct(org.bouncycastle.math.ec.ECFieldElement paramECFieldElement1, org.bouncycastle.math.ec.ECFieldElement paramECFieldElement2) {
    return square().add(paramECFieldElement1.multiply(paramECFieldElement2));
  }
  
  public org.bouncycastle.math.ec.ECFieldElement squarePow(int paramInt) {
    org.bouncycastle.math.ec.ECFieldElement eCFieldElement = this;
    for (byte b = 0; b < paramInt; b++)
      eCFieldElement = eCFieldElement.square(); 
    return eCFieldElement;
  }
  
  public boolean testBitZero() {
    return toBigInteger().testBit(0);
  }
  
  public String toString() {
    return toBigInteger().toString(16);
  }
  
  public byte[] getEncoded() {
    return BigIntegers.asUnsignedByteArray((getFieldSize() + 7) / 8, toBigInteger());
  }
}
