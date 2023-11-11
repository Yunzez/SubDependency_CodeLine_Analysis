package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

public class SPHINCSPlusPublicKeyParameters extends SPHINCSPlusKeyParameters {
  private final PK pk;
  
  public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters paramSPHINCSPlusParameters, byte[] paramArrayOfbyte) {
    super(false, paramSPHINCSPlusParameters);
    int i = (paramSPHINCSPlusParameters.getEngine()).N;
    if (paramArrayOfbyte.length != 2 * i)
      throw new IllegalArgumentException("public key encoding does not match parameters"); 
    this.pk = new PK(Arrays.copyOfRange(paramArrayOfbyte, 0, i), Arrays.copyOfRange(paramArrayOfbyte, i, 2 * i));
  }
  
  SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters paramSPHINCSPlusParameters, PK paramPK) {
    super(false, paramSPHINCSPlusParameters);
    this.pk = paramPK;
  }
  
  public byte[] getSeed() {
    return Arrays.clone(this.pk.seed);
  }
  
  public byte[] getRoot() {
    return Arrays.clone(this.pk.root);
  }
  
  public byte[] getEncoded() {
    return Arrays.concatenate(this.pk.seed, this.pk.root);
  }
}
