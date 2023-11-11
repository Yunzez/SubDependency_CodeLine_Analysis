package META-INF.versions.9.org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

public class DSAValidationParameters {
  private int usageIndex;
  
  private byte[] seed;
  
  private int counter;
  
  public DSAValidationParameters(byte[] paramArrayOfbyte, int paramInt) {
    this(paramArrayOfbyte, paramInt, -1);
  }
  
  public DSAValidationParameters(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.seed = Arrays.clone(paramArrayOfbyte);
    this.counter = paramInt1;
    this.usageIndex = paramInt2;
  }
  
  public int getCounter() {
    return this.counter;
  }
  
  public byte[] getSeed() {
    return Arrays.clone(this.seed);
  }
  
  public int getUsageIndex() {
    return this.usageIndex;
  }
  
  public int hashCode() {
    return this.counter ^ Arrays.hashCode(this.seed);
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof org.bouncycastle.crypto.params.DSAValidationParameters))
      return false; 
    org.bouncycastle.crypto.params.DSAValidationParameters dSAValidationParameters = (org.bouncycastle.crypto.params.DSAValidationParameters)paramObject;
    if (dSAValidationParameters.counter != this.counter)
      return false; 
    return Arrays.areEqual(this.seed, dSAValidationParameters.seed);
  }
}
