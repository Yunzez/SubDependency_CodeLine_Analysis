package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.CipherParameters;

public class RainbowParameters implements CipherParameters {
  private final int[] DEFAULT_VI = new int[] { 6, 12, 17, 22, 33 };
  
  private int[] vi = this.DEFAULT_VI;
  
  public RainbowParameters() {}
  
  public RainbowParameters(int[] paramArrayOfint) {
    checkParams();
  }
  
  private void checkParams() {
    if (this.vi == null)
      throw new IllegalArgumentException("no layers defined."); 
    if (this.vi.length > 1) {
      for (byte b = 0; b < this.vi.length - 1; b++) {
        if (this.vi[b] >= this.vi[b + 1])
          throw new IllegalArgumentException("v[i] has to be smaller than v[i+1]"); 
      } 
    } else {
      throw new IllegalArgumentException("Rainbow needs at least 1 layer, such that v1 < v2.");
    } 
  }
  
  public int getNumOfLayers() {
    return this.vi.length - 1;
  }
  
  public int getDocLength() {
    return this.vi[this.vi.length - 1] - this.vi[0];
  }
  
  public int[] getVi() {
    return this.vi;
  }
}
