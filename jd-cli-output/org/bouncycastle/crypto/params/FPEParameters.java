package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

public final class FPEParameters implements CipherParameters {
  private final KeyParameter key;
  
  private final int radix;
  
  private final byte[] tweak;
  
  private final boolean useInverse;
  
  public FPEParameters(KeyParameter paramKeyParameter, int paramInt, byte[] paramArrayOfbyte) {
    this(paramKeyParameter, paramInt, paramArrayOfbyte, false);
  }
  
  public FPEParameters(KeyParameter paramKeyParameter, int paramInt, byte[] paramArrayOfbyte, boolean paramBoolean) {
    this.key = paramKeyParameter;
    this.radix = paramInt;
    this.tweak = Arrays.clone(paramArrayOfbyte);
    this.useInverse = paramBoolean;
  }
  
  public KeyParameter getKey() {
    return this.key;
  }
  
  public int getRadix() {
    return this.radix;
  }
  
  public byte[] getTweak() {
    return Arrays.clone(this.tweak);
  }
  
  public boolean isUsingInverseFunction() {
    return this.useInverse;
  }
}
