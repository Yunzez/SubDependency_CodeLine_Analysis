package META-INF.versions.9.org.bouncycastle.math.field;

import java.math.BigInteger;
import org.bouncycastle.math.field.FiniteField;

class PrimeField implements FiniteField {
  protected final BigInteger characteristic;
  
  PrimeField(BigInteger paramBigInteger) {
    this.characteristic = paramBigInteger;
  }
  
  public BigInteger getCharacteristic() {
    return this.characteristic;
  }
  
  public int getDimension() {
    return 1;
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (!(paramObject instanceof org.bouncycastle.math.field.PrimeField))
      return false; 
    org.bouncycastle.math.field.PrimeField primeField = (org.bouncycastle.math.field.PrimeField)paramObject;
    return this.characteristic.equals(primeField.characteristic);
  }
  
  public int hashCode() {
    return this.characteristic.hashCode();
  }
}
