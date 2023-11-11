package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;

public class Blake2xsDigest implements Xof {
  public static final int UNKNOWN_DIGEST_LENGTH = 65535;
  
  private static final int DIGEST_LENGTH = 32;
  
  private static final long MAX_NUMBER_BLOCKS = 4294967296L;
  
  private int digestLength;
  
  private Blake2sDigest hash;
  
  private byte[] h0 = null;
  
  private byte[] buf = new byte[32];
  
  private int bufPos = 32;
  
  private int digestPos = 0;
  
  private long blockPos = 0L;
  
  private long nodeOffset;
  
  public Blake2xsDigest() {
    this(65535);
  }
  
  public Blake2xsDigest(int paramInt) {
    this(paramInt, null, null, null);
  }
  
  public Blake2xsDigest(int paramInt, byte[] paramArrayOfbyte) {
    this(paramInt, paramArrayOfbyte, null, null);
  }
  
  public Blake2xsDigest(int paramInt, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    if (paramInt < 1 || paramInt > 65535)
      throw new IllegalArgumentException("BLAKE2xs digest length must be between 1 and 2^16-1"); 
    this.digestLength = paramInt;
    this.nodeOffset = computeNodeOffset();
    this.hash = new Blake2sDigest(32, paramArrayOfbyte1, paramArrayOfbyte2, paramArrayOfbyte3, this.nodeOffset);
  }
  
  public Blake2xsDigest(Blake2xsDigest paramBlake2xsDigest) {
    this.digestLength = paramBlake2xsDigest.digestLength;
    this.hash = new Blake2sDigest(paramBlake2xsDigest.hash);
    this.h0 = Arrays.clone(paramBlake2xsDigest.h0);
    this.buf = Arrays.clone(paramBlake2xsDigest.buf);
    this.bufPos = paramBlake2xsDigest.bufPos;
    this.digestPos = paramBlake2xsDigest.digestPos;
    this.blockPos = paramBlake2xsDigest.blockPos;
    this.nodeOffset = paramBlake2xsDigest.nodeOffset;
  }
  
  public String getAlgorithmName() {
    return "BLAKE2xs";
  }
  
  public int getDigestSize() {
    return this.digestLength;
  }
  
  public int getByteLength() {
    return this.hash.getByteLength();
  }
  
  public long getUnknownMaxLength() {
    return 137438953472L;
  }
  
  public void update(byte paramByte) {
    this.hash.update(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.hash.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public void reset() {
    this.hash.reset();
    this.h0 = null;
    this.bufPos = 32;
    this.digestPos = 0;
    this.blockPos = 0L;
    this.nodeOffset = computeNodeOffset();
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    return doFinal(paramArrayOfbyte, paramInt, paramArrayOfbyte.length);
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    int i = doOutput(paramArrayOfbyte, paramInt1, paramInt2);
    reset();
    return i;
  }
  
  public int doOutput(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.h0 == null) {
      this.h0 = new byte[this.hash.getDigestSize()];
      this.hash.doFinal(this.h0, 0);
    } 
    if (this.digestLength != 65535) {
      if (this.digestPos + paramInt2 > this.digestLength)
        throw new IllegalArgumentException("Output length is above the digest length"); 
    } else if (this.blockPos << 5L >= getUnknownMaxLength()) {
      throw new IllegalArgumentException("Maximum length is 2^32 blocks of 32 bytes");
    } 
    for (byte b = 0; b < paramInt2; b++) {
      if (this.bufPos >= 32) {
        Blake2sDigest blake2sDigest = new Blake2sDigest(computeStepLength(), 32, this.nodeOffset);
        blake2sDigest.update(this.h0, 0, this.h0.length);
        Arrays.fill(this.buf, (byte)0);
        blake2sDigest.doFinal(this.buf, 0);
        this.bufPos = 0;
        this.nodeOffset++;
        this.blockPos++;
      } 
      paramArrayOfbyte[b] = this.buf[this.bufPos];
      this.bufPos++;
      this.digestPos++;
    } 
    return paramInt2;
  }
  
  private int computeStepLength() {
    return (this.digestLength == 65535) ? 32 : Math.min(32, this.digestLength - this.digestPos);
  }
  
  private long computeNodeOffset() {
    return this.digestLength * 4294967296L;
  }
}
