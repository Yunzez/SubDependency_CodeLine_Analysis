package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.params.Blake3Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class Blake3Mac implements Mac {
  private final Blake3Digest theDigest;
  
  public Blake3Mac(Blake3Digest paramBlake3Digest) {
    this.theDigest = paramBlake3Digest;
  }
  
  public String getAlgorithmName() {
    return this.theDigest.getAlgorithmName() + "Mac";
  }
  
  public void init(CipherParameters paramCipherParameters) {
    CipherParameters cipherParameters = paramCipherParameters;
    if (cipherParameters instanceof KeyParameter)
      cipherParameters = Blake3Parameters.key(((KeyParameter)cipherParameters).getKey()); 
    if (!(cipherParameters instanceof Blake3Parameters))
      throw new IllegalArgumentException("Invalid parameter passed to Blake3Mac init - " + paramCipherParameters.getClass().getName()); 
    Blake3Parameters blake3Parameters = (Blake3Parameters)cipherParameters;
    if (blake3Parameters.getKey() == null)
      throw new IllegalArgumentException("Blake3Mac requires a key parameter."); 
    this.theDigest.init(blake3Parameters);
  }
  
  public int getMacSize() {
    return this.theDigest.getDigestSize();
  }
  
  public void update(byte paramByte) {
    this.theDigest.update(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.theDigest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    return this.theDigest.doFinal(paramArrayOfbyte, paramInt);
  }
  
  public void reset() {
    this.theDigest.reset();
  }
}
