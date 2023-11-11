package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Arrays;

public class SM2ParameterSpec implements AlgorithmParameterSpec {
  private byte[] id;
  
  public SM2ParameterSpec(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte == null)
      throw new NullPointerException("id string cannot be null"); 
    this.id = Arrays.clone(paramArrayOfbyte);
  }
  
  public byte[] getID() {
    return Arrays.clone(this.id);
  }
}
