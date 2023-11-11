package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

public class SPHINCSPlusPrivateKeyParameters extends SPHINCSPlusKeyParameters {
  final SK sk;
  
  final PK pk;
  
  public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters paramSPHINCSPlusParameters, byte[] paramArrayOfbyte) {
    super(true, paramSPHINCSPlusParameters);
    int i = (paramSPHINCSPlusParameters.getEngine()).N;
    if (paramArrayOfbyte.length != 4 * i)
      throw new IllegalArgumentException("private key encoding does not match parameters"); 
    this.sk = new SK(Arrays.copyOfRange(paramArrayOfbyte, 0, i), Arrays.copyOfRange(paramArrayOfbyte, i, 2 * i));
    this.pk = new PK(Arrays.copyOfRange(paramArrayOfbyte, 2 * i, 3 * i), Arrays.copyOfRange(paramArrayOfbyte, 3 * i, 4 * i));
  }
  
  SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters paramSPHINCSPlusParameters, SK paramSK, PK paramPK) {
    super(true, paramSPHINCSPlusParameters);
    this.sk = paramSK;
    this.pk = paramPK;
  }
  
  public byte[] getSeed() {
    return Arrays.clone(this.sk.seed);
  }
  
  public byte[] getPrf() {
    return Arrays.clone(this.sk.prf);
  }
  
  public byte[] getPublicSeed() {
    return Arrays.clone(this.pk.seed);
  }
  
  public byte[] getPublicKey() {
    return Arrays.concatenate(this.pk.seed, this.pk.root);
  }
  
  public byte[] getEncoded() {
    return Arrays.concatenate(this.sk.seed, this.sk.prf, this.pk.seed, this.pk.root);
  }
}
