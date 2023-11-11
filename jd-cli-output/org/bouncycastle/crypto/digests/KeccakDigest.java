package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class KeccakDigest implements ExtendedDigest {
  private static long[] KeccakRoundConstants = new long[] { 
      1L, 32898L, -9223372036854742902L, -9223372034707259392L, 32907L, 2147483649L, -9223372034707259263L, -9223372036854743031L, 138L, 136L, 
      2147516425L, 2147483658L, 2147516555L, -9223372036854775669L, -9223372036854742903L, -9223372036854743037L, -9223372036854743038L, -9223372036854775680L, 32778L, -9223372034707292150L, 
      -9223372034707259263L, -9223372036854742912L, 2147483649L, -9223372034707259384L };
  
  protected long[] state = new long[25];
  
  protected byte[] dataQueue = new byte[192];
  
  protected int rate;
  
  protected int bitsInQueue;
  
  protected int fixedOutputLength;
  
  protected boolean squeezing;
  
  public KeccakDigest() {
    this(288);
  }
  
  public KeccakDigest(int paramInt) {
    init(paramInt);
  }
  
  public KeccakDigest(KeccakDigest paramKeccakDigest) {
    System.arraycopy(paramKeccakDigest.state, 0, this.state, 0, paramKeccakDigest.state.length);
    System.arraycopy(paramKeccakDigest.dataQueue, 0, this.dataQueue, 0, paramKeccakDigest.dataQueue.length);
    this.rate = paramKeccakDigest.rate;
    this.bitsInQueue = paramKeccakDigest.bitsInQueue;
    this.fixedOutputLength = paramKeccakDigest.fixedOutputLength;
    this.squeezing = paramKeccakDigest.squeezing;
  }
  
  public String getAlgorithmName() {
    return "Keccak-" + this.fixedOutputLength;
  }
  
  public int getDigestSize() {
    return this.fixedOutputLength / 8;
  }
  
  public void update(byte paramByte) {
    absorb(paramByte);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    absorb(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    squeeze(paramArrayOfbyte, paramInt, this.fixedOutputLength);
    reset();
    return getDigestSize();
  }
  
  protected int doFinal(byte[] paramArrayOfbyte, int paramInt1, byte paramByte, int paramInt2) {
    if (paramInt2 > 0)
      absorbBits(paramByte, paramInt2); 
    squeeze(paramArrayOfbyte, paramInt1, this.fixedOutputLength);
    reset();
    return getDigestSize();
  }
  
  public void reset() {
    init(this.fixedOutputLength);
  }
  
  public int getByteLength() {
    return this.rate / 8;
  }
  
  private void init(int paramInt) {
    switch (paramInt) {
      case 128:
      case 224:
      case 256:
      case 288:
      case 384:
      case 512:
        initSponge(1600 - (paramInt << 1));
        return;
    } 
    throw new IllegalArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
  }
  
  private void initSponge(int paramInt) {
    if (paramInt <= 0 || paramInt >= 1600 || paramInt % 64 != 0)
      throw new IllegalStateException("invalid rate value"); 
    this.rate = paramInt;
    for (byte b = 0; b < this.state.length; b++)
      this.state[b] = 0L; 
    Arrays.fill(this.dataQueue, (byte)0);
    this.bitsInQueue = 0;
    this.squeezing = false;
    this.fixedOutputLength = (1600 - paramInt) / 2;
  }
  
  protected void absorb(byte paramByte) {
    if (this.bitsInQueue % 8 != 0)
      throw new IllegalStateException("attempt to absorb with odd length queue"); 
    if (this.squeezing)
      throw new IllegalStateException("attempt to absorb while squeezing"); 
    this.dataQueue[this.bitsInQueue >>> 3] = paramByte;
    if ((this.bitsInQueue += 8) == this.rate) {
      KeccakAbsorb(this.dataQueue, 0);
      this.bitsInQueue = 0;
    } 
  }
  
  protected void absorb(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.bitsInQueue % 8 != 0)
      throw new IllegalStateException("attempt to absorb with odd length queue"); 
    if (this.squeezing)
      throw new IllegalStateException("attempt to absorb while squeezing"); 
    int i = this.bitsInQueue >>> 3;
    int j = this.rate >>> 3;
    int k = j - i;
    if (paramInt2 < k) {
      System.arraycopy(paramArrayOfbyte, paramInt1, this.dataQueue, i, paramInt2);
      this.bitsInQueue += paramInt2 << 3;
      return;
    } 
    int m = 0;
    if (i > 0) {
      System.arraycopy(paramArrayOfbyte, paramInt1, this.dataQueue, i, k);
      m += k;
      KeccakAbsorb(this.dataQueue, 0);
    } 
    int n;
    while ((n = paramInt2 - m) >= j) {
      KeccakAbsorb(paramArrayOfbyte, paramInt1 + m);
      m += j;
    } 
    System.arraycopy(paramArrayOfbyte, paramInt1 + m, this.dataQueue, 0, n);
    this.bitsInQueue = n << 3;
  }
  
  protected void absorbBits(int paramInt1, int paramInt2) {
    if (paramInt2 < 1 || paramInt2 > 7)
      throw new IllegalArgumentException("'bits' must be in the range 1 to 7"); 
    if (this.bitsInQueue % 8 != 0)
      throw new IllegalStateException("attempt to absorb with odd length queue"); 
    if (this.squeezing)
      throw new IllegalStateException("attempt to absorb while squeezing"); 
    int i = (1 << paramInt2) - 1;
    this.dataQueue[this.bitsInQueue >>> 3] = (byte)(paramInt1 & i);
    this.bitsInQueue += paramInt2;
  }
  
  private void padAndSwitchToSqueezingPhase() {
    this.dataQueue[this.bitsInQueue >>> 3] = (byte)(this.dataQueue[this.bitsInQueue >>> 3] | (byte)(1 << (this.bitsInQueue & 0x7)));
    if (++this.bitsInQueue == this.rate) {
      KeccakAbsorb(this.dataQueue, 0);
    } else {
      int i = this.bitsInQueue >>> 6;
      int j = this.bitsInQueue & 0x3F;
      boolean bool = false;
      for (byte b = 0; b < i; b++) {
        this.state[b] = this.state[b] ^ Pack.littleEndianToLong(this.dataQueue, bool);
        bool += true;
      } 
      if (j > 0) {
        long l = (1L << j) - 1L;
        this.state[i] = this.state[i] ^ Pack.littleEndianToLong(this.dataQueue, bool) & l;
      } 
    } 
    this.state[this.rate - 1 >>> 6] = this.state[this.rate - 1 >>> 6] ^ Long.MIN_VALUE;
    this.bitsInQueue = 0;
    this.squeezing = true;
  }
  
  protected void squeeze(byte[] paramArrayOfbyte, int paramInt, long paramLong) {
    if (!this.squeezing)
      padAndSwitchToSqueezingPhase(); 
    if (paramLong % 8L != 0L)
      throw new IllegalStateException("outputLength not a multiple of 8"); 
    long l;
    for (l = 0L; l < paramLong; l += i) {
      if (this.bitsInQueue == 0)
        KeccakExtract(); 
      int i = (int)Math.min(this.bitsInQueue, paramLong - l);
      System.arraycopy(this.dataQueue, (this.rate - this.bitsInQueue) / 8, paramArrayOfbyte, paramInt + (int)(l / 8L), i / 8);
      this.bitsInQueue -= i;
    } 
  }
  
  private void KeccakAbsorb(byte[] paramArrayOfbyte, int paramInt) {
    int i = this.rate >>> 6;
    for (byte b = 0; b < i; b++) {
      this.state[b] = this.state[b] ^ Pack.littleEndianToLong(paramArrayOfbyte, paramInt);
      paramInt += 8;
    } 
    KeccakPermutation();
  }
  
  private void KeccakExtract() {
    KeccakPermutation();
    Pack.longToLittleEndian(this.state, 0, this.rate >>> 6, this.dataQueue, 0);
    this.bitsInQueue = this.rate;
  }
  
  private void KeccakPermutation() {
    long[] arrayOfLong = this.state;
    long l1 = arrayOfLong[0];
    long l2 = arrayOfLong[1];
    long l3 = arrayOfLong[2];
    long l4 = arrayOfLong[3];
    long l5 = arrayOfLong[4];
    long l6 = arrayOfLong[5];
    long l7 = arrayOfLong[6];
    long l8 = arrayOfLong[7];
    long l9 = arrayOfLong[8];
    long l10 = arrayOfLong[9];
    long l11 = arrayOfLong[10];
    long l12 = arrayOfLong[11];
    long l13 = arrayOfLong[12];
    long l14 = arrayOfLong[13];
    long l15 = arrayOfLong[14];
    long l16 = arrayOfLong[15];
    long l17 = arrayOfLong[16];
    long l18 = arrayOfLong[17];
    long l19 = arrayOfLong[18];
    long l20 = arrayOfLong[19];
    long l21 = arrayOfLong[20];
    long l22 = arrayOfLong[21];
    long l23 = arrayOfLong[22];
    long l24 = arrayOfLong[23];
    long l25 = arrayOfLong[24];
    for (byte b = 0; b < 24; b++) {
      long l26 = l1 ^ l6 ^ l11 ^ l16 ^ l21;
      long l27 = l2 ^ l7 ^ l12 ^ l17 ^ l22;
      long l28 = l3 ^ l8 ^ l13 ^ l18 ^ l23;
      long l29 = l4 ^ l9 ^ l14 ^ l19 ^ l24;
      long l30 = l5 ^ l10 ^ l15 ^ l20 ^ l25;
      long l31 = (l27 << 1L | l27 >>> -1L) ^ l30;
      long l32 = (l28 << 1L | l28 >>> -1L) ^ l26;
      long l33 = (l29 << 1L | l29 >>> -1L) ^ l27;
      long l34 = (l30 << 1L | l30 >>> -1L) ^ l28;
      long l35 = (l26 << 1L | l26 >>> -1L) ^ l29;
      l1 ^= l31;
      l6 ^= l31;
      l11 ^= l31;
      l16 ^= l31;
      l21 ^= l31;
      l2 ^= l32;
      l7 ^= l32;
      l12 ^= l32;
      l17 ^= l32;
      l22 ^= l32;
      l3 ^= l33;
      l8 ^= l33;
      l13 ^= l33;
      l18 ^= l33;
      l23 ^= l33;
      l4 ^= l34;
      l9 ^= l34;
      l14 ^= l34;
      l19 ^= l34;
      l24 ^= l34;
      l5 ^= l35;
      l10 ^= l35;
      l15 ^= l35;
      l20 ^= l35;
      l25 ^= l35;
      l27 = l2 << 1L | l2 >>> 63L;
      l2 = l7 << 44L | l7 >>> 20L;
      l7 = l10 << 20L | l10 >>> 44L;
      l10 = l23 << 61L | l23 >>> 3L;
      l23 = l15 << 39L | l15 >>> 25L;
      l15 = l21 << 18L | l21 >>> 46L;
      l21 = l3 << 62L | l3 >>> 2L;
      l3 = l13 << 43L | l13 >>> 21L;
      l13 = l14 << 25L | l14 >>> 39L;
      l14 = l20 << 8L | l20 >>> 56L;
      l20 = l24 << 56L | l24 >>> 8L;
      l24 = l16 << 41L | l16 >>> 23L;
      l16 = l5 << 27L | l5 >>> 37L;
      l5 = l25 << 14L | l25 >>> 50L;
      l25 = l22 << 2L | l22 >>> 62L;
      l22 = l9 << 55L | l9 >>> 9L;
      l9 = l17 << 45L | l17 >>> 19L;
      l17 = l6 << 36L | l6 >>> 28L;
      l6 = l4 << 28L | l4 >>> 36L;
      l4 = l19 << 21L | l19 >>> 43L;
      l19 = l18 << 15L | l18 >>> 49L;
      l18 = l12 << 10L | l12 >>> 54L;
      l12 = l8 << 6L | l8 >>> 58L;
      l8 = l11 << 3L | l11 >>> 61L;
      l11 = l27;
      l26 = l1 ^ (l2 ^ 0xFFFFFFFFFFFFFFFFL) & l3;
      l27 = l2 ^ (l3 ^ 0xFFFFFFFFFFFFFFFFL) & l4;
      l3 ^= (l4 ^ 0xFFFFFFFFFFFFFFFFL) & l5;
      l4 ^= (l5 ^ 0xFFFFFFFFFFFFFFFFL) & l1;
      l5 ^= (l1 ^ 0xFFFFFFFFFFFFFFFFL) & l2;
      l1 = l26;
      l2 = l27;
      l26 = l6 ^ (l7 ^ 0xFFFFFFFFFFFFFFFFL) & l8;
      l27 = l7 ^ (l8 ^ 0xFFFFFFFFFFFFFFFFL) & l9;
      l8 ^= (l9 ^ 0xFFFFFFFFFFFFFFFFL) & l10;
      l9 ^= (l10 ^ 0xFFFFFFFFFFFFFFFFL) & l6;
      l10 ^= (l6 ^ 0xFFFFFFFFFFFFFFFFL) & l7;
      l6 = l26;
      l7 = l27;
      l26 = l11 ^ (l12 ^ 0xFFFFFFFFFFFFFFFFL) & l13;
      l27 = l12 ^ (l13 ^ 0xFFFFFFFFFFFFFFFFL) & l14;
      l13 ^= (l14 ^ 0xFFFFFFFFFFFFFFFFL) & l15;
      l14 ^= (l15 ^ 0xFFFFFFFFFFFFFFFFL) & l11;
      l15 ^= (l11 ^ 0xFFFFFFFFFFFFFFFFL) & l12;
      l11 = l26;
      l12 = l27;
      l26 = l16 ^ (l17 ^ 0xFFFFFFFFFFFFFFFFL) & l18;
      l27 = l17 ^ (l18 ^ 0xFFFFFFFFFFFFFFFFL) & l19;
      l18 ^= (l19 ^ 0xFFFFFFFFFFFFFFFFL) & l20;
      l19 ^= (l20 ^ 0xFFFFFFFFFFFFFFFFL) & l16;
      l20 ^= (l16 ^ 0xFFFFFFFFFFFFFFFFL) & l17;
      l16 = l26;
      l17 = l27;
      l26 = l21 ^ (l22 ^ 0xFFFFFFFFFFFFFFFFL) & l23;
      l27 = l22 ^ (l23 ^ 0xFFFFFFFFFFFFFFFFL) & l24;
      l23 ^= (l24 ^ 0xFFFFFFFFFFFFFFFFL) & l25;
      l24 ^= (l25 ^ 0xFFFFFFFFFFFFFFFFL) & l21;
      l25 ^= (l21 ^ 0xFFFFFFFFFFFFFFFFL) & l22;
      l21 = l26;
      l22 = l27;
      l1 ^= KeccakRoundConstants[b];
    } 
    arrayOfLong[0] = l1;
    arrayOfLong[1] = l2;
    arrayOfLong[2] = l3;
    arrayOfLong[3] = l4;
    arrayOfLong[4] = l5;
    arrayOfLong[5] = l6;
    arrayOfLong[6] = l7;
    arrayOfLong[7] = l8;
    arrayOfLong[8] = l9;
    arrayOfLong[9] = l10;
    arrayOfLong[10] = l11;
    arrayOfLong[11] = l12;
    arrayOfLong[12] = l13;
    arrayOfLong[13] = l14;
    arrayOfLong[14] = l15;
    arrayOfLong[15] = l16;
    arrayOfLong[16] = l17;
    arrayOfLong[17] = l18;
    arrayOfLong[18] = l19;
    arrayOfLong[19] = l20;
    arrayOfLong[20] = l21;
    arrayOfLong[21] = l22;
    arrayOfLong[22] = l23;
    arrayOfLong[23] = l24;
    arrayOfLong[24] = l25;
  }
}
