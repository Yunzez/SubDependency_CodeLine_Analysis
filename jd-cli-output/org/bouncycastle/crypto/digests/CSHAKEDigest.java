package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

public class CSHAKEDigest extends SHAKEDigest {
  private static final byte[] padding = new byte[100];
  
  private final byte[] diff;
  
  public CSHAKEDigest(int paramInt, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    super(paramInt);
    if ((paramArrayOfbyte1 == null || paramArrayOfbyte1.length == 0) && (paramArrayOfbyte2 == null || paramArrayOfbyte2.length == 0)) {
      this.diff = null;
    } else {
      this.diff = Arrays.concatenate(XofUtils.leftEncode((this.rate / 8)), encodeString(paramArrayOfbyte1), encodeString(paramArrayOfbyte2));
      diffPadAndAbsorb();
    } 
  }
  
  CSHAKEDigest(CSHAKEDigest paramCSHAKEDigest) {
    super(paramCSHAKEDigest);
    this.diff = Arrays.clone(paramCSHAKEDigest.diff);
  }
  
  private void diffPadAndAbsorb() {
    int i = this.rate / 8;
    absorb(this.diff, 0, this.diff.length);
    int j = this.diff.length % i;
    if (j != 0) {
      int k;
      for (k = i - j; k > padding.length; k -= padding.length)
        absorb(padding, 0, padding.length); 
      absorb(padding, 0, k);
    } 
  }
  
  private byte[] encodeString(byte[] paramArrayOfbyte) {
    return (paramArrayOfbyte == null || paramArrayOfbyte.length == 0) ? XofUtils.leftEncode(0L) : Arrays.concatenate(XofUtils.leftEncode(paramArrayOfbyte.length * 8L), paramArrayOfbyte);
  }
  
  public String getAlgorithmName() {
    return "CSHAKE" + this.fixedOutputLength;
  }
  
  public int doOutput(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.diff != null) {
      if (!this.squeezing)
        absorbBits(0, 2); 
      squeeze(paramArrayOfbyte, paramInt1, paramInt2 * 8L);
      return paramInt2;
    } 
    return super.doOutput(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public void reset() {
    super.reset();
    if (this.diff != null)
      diffPadAndAbsorb(); 
  }
}
