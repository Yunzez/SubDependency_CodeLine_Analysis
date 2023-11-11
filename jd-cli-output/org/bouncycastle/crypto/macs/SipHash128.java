package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.Pack;

public class SipHash128 extends SipHash {
  public SipHash128() {}
  
  public SipHash128(int paramInt1, int paramInt2) {
    super(paramInt1, paramInt2);
  }
  
  public String getAlgorithmName() {
    return "SipHash128-" + this.c + "-" + this.d;
  }
  
  public int getMacSize() {
    return 16;
  }
  
  public long doFinal() throws DataLengthException, IllegalStateException {
    throw new UnsupportedOperationException("doFinal() is not supported");
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) throws DataLengthException, IllegalStateException {
    this.m >>>= 7 - this.wordPos << 3;
    this.m >>>= 8L;
    this.m |= (((this.wordCount << 3) + this.wordPos) & 0xFFL) << 56L;
    processMessageWord();
    this.v2 ^= 0xEEL;
    applySipRounds(this.d);
    long l1 = this.v0 ^ this.v1 ^ this.v2 ^ this.v3;
    this.v1 ^= 0xDDL;
    applySipRounds(this.d);
    long l2 = this.v0 ^ this.v1 ^ this.v2 ^ this.v3;
    reset();
    Pack.longToLittleEndian(l1, paramArrayOfbyte, paramInt);
    Pack.longToLittleEndian(l2, paramArrayOfbyte, paramInt + 8);
    return 16;
  }
  
  public void reset() {
    super.reset();
    this.v1 ^= 0xEEL;
  }
}
