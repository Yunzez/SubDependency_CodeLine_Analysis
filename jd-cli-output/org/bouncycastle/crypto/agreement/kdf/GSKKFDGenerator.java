package org.bouncycastle.crypto.agreement.kdf;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class GSKKFDGenerator implements DigestDerivationFunction {
  private final Digest digest;
  
  private byte[] z;
  
  private int counter;
  
  private byte[] r;
  
  private byte[] buf;
  
  public GSKKFDGenerator(Digest paramDigest) {
    this.digest = paramDigest;
    this.buf = new byte[paramDigest.getDigestSize()];
  }
  
  public Digest getDigest() {
    return this.digest;
  }
  
  public void init(DerivationParameters paramDerivationParameters) {
    if (paramDerivationParameters instanceof GSKKDFParameters) {
      this.z = ((GSKKDFParameters)paramDerivationParameters).getZ();
      this.counter = ((GSKKDFParameters)paramDerivationParameters).getStartCounter();
      this.r = ((GSKKDFParameters)paramDerivationParameters).getNonce();
    } else {
      throw new IllegalArgumentException("unkown parameters type");
    } 
  }
  
  public int generateBytes(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws DataLengthException, IllegalArgumentException {
    if (paramInt1 + paramInt2 > paramArrayOfbyte.length)
      throw new DataLengthException("output buffer too small"); 
    this.digest.update(this.z, 0, this.z.length);
    byte[] arrayOfByte = Pack.intToBigEndian(this.counter++);
    this.digest.update(arrayOfByte, 0, arrayOfByte.length);
    if (this.r != null)
      this.digest.update(this.r, 0, this.r.length); 
    this.digest.doFinal(this.buf, 0);
    System.arraycopy(this.buf, 0, paramArrayOfbyte, paramInt1, paramInt2);
    Arrays.clear(this.buf);
    return paramInt2;
  }
}
