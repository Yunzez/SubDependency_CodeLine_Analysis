package org.bouncycastle.jcajce.provider.digest;

import java.security.DigestException;
import java.security.MessageDigest;
import org.bouncycastle.crypto.Digest;

public class BCMessageDigest extends MessageDigest {
  protected Digest digest;
  
  protected int digestSize;
  
  protected BCMessageDigest(Digest paramDigest) {
    super(paramDigest.getAlgorithmName());
    this.digest = paramDigest;
    this.digestSize = paramDigest.getDigestSize();
  }
  
  public void engineReset() {
    this.digest.reset();
  }
  
  public void engineUpdate(byte paramByte) {
    this.digest.update(paramByte);
  }
  
  public void engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int engineGetDigestLength() {
    return this.digestSize;
  }
  
  public byte[] engineDigest() {
    byte[] arrayOfByte = new byte[this.digestSize];
    this.digest.doFinal(arrayOfByte, 0);
    return arrayOfByte;
  }
  
  public int engineDigest(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws DigestException {
    if (paramInt2 < this.digestSize)
      throw new DigestException("partial digests not returned"); 
    if (paramArrayOfbyte.length - paramInt1 < this.digestSize)
      throw new DigestException("insufficient space in the output buffer to store the digest"); 
    this.digest.doFinal(paramArrayOfbyte, paramInt1);
    return this.digestSize;
  }
}
