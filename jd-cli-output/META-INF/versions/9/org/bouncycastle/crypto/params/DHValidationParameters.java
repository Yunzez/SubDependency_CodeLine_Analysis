package META-INF.versions.9.org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

public class DHValidationParameters {
  private byte[] seed;
  
  private int counter;
  
  public DHValidationParameters(byte[] paramArrayOfbyte, int paramInt) {
    this.seed = Arrays.clone(paramArrayOfbyte);
    this.counter = paramInt;
  }
  
  public int getCounter() {
    return this.counter;
  }
  
  public byte[] getSeed() {
    return Arrays.clone(this.seed);
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof org.bouncycastle.crypto.params.DHValidationParameters))
      return false; 
    org.bouncycastle.crypto.params.DHValidationParameters dHValidationParameters = (org.bouncycastle.crypto.params.DHValidationParameters)paramObject;
    if (dHValidationParameters.counter != this.counter)
      return false; 
    return Arrays.areEqual(this.seed, dHValidationParameters.seed);
  }
  
  public int hashCode() {
    return this.counter ^ Arrays.hashCode(this.seed);
  }
}
