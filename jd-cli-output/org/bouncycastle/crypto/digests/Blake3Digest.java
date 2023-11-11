package org.bouncycastle.crypto.digests;

import java.util.Iterator;
import java.util.Stack;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.params.Blake3Parameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

public class Blake3Digest implements ExtendedDigest, Memoable, Xof {
  private static final String ERR_OUTPUTTING = "Already outputting";
  
  private static final int NUMWORDS = 8;
  
  private static final int ROUNDS = 7;
  
  private static final int BLOCKLEN = 64;
  
  private static final int CHUNKLEN = 1024;
  
  private static final int CHUNKSTART = 1;
  
  private static final int CHUNKEND = 2;
  
  private static final int PARENT = 4;
  
  private static final int ROOT = 8;
  
  private static final int KEYEDHASH = 16;
  
  private static final int DERIVECONTEXT = 32;
  
  private static final int DERIVEKEY = 64;
  
  private static final int CHAINING0 = 0;
  
  private static final int CHAINING1 = 1;
  
  private static final int CHAINING2 = 2;
  
  private static final int CHAINING3 = 3;
  
  private static final int CHAINING4 = 4;
  
  private static final int CHAINING5 = 5;
  
  private static final int CHAINING6 = 6;
  
  private static final int CHAINING7 = 7;
  
  private static final int IV0 = 8;
  
  private static final int IV1 = 9;
  
  private static final int IV2 = 10;
  
  private static final int IV3 = 11;
  
  private static final int COUNT0 = 12;
  
  private static final int COUNT1 = 13;
  
  private static final int DATALEN = 14;
  
  private static final int FLAGS = 15;
  
  private static final byte[] SIGMA = new byte[] { 
      2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 
      12, 5, 9, 14, 15, 8 };
  
  private static final byte[] ROTATE = new byte[] { 16, 12, 8, 7 };
  
  private static final int[] IV = new int[] { 1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225 };
  
  private final byte[] theBuffer = new byte[64];
  
  private final int[] theK = new int[8];
  
  private final int[] theChaining = new int[8];
  
  private final int[] theV = new int[16];
  
  private final int[] theM = new int[16];
  
  private final byte[] theIndices = new byte[16];
  
  private final Stack theStack = new Stack();
  
  private final int theDigestLen;
  
  private boolean outputting;
  
  private long outputAvailable;
  
  private int theMode;
  
  private int theOutputMode;
  
  private int theOutputDataLen;
  
  private long theCounter;
  
  private int theCurrBytes;
  
  private int thePos;
  
  public Blake3Digest() {
    this(32);
  }
  
  public Blake3Digest(int paramInt) {
    this.theDigestLen = paramInt;
    init(null);
  }
  
  private Blake3Digest(Blake3Digest paramBlake3Digest) {
    this.theDigestLen = paramBlake3Digest.theDigestLen;
    reset(paramBlake3Digest);
  }
  
  public int getByteLength() {
    return 64;
  }
  
  public String getAlgorithmName() {
    return "BLAKE3";
  }
  
  public int getDigestSize() {
    return this.theDigestLen;
  }
  
  public void init(Blake3Parameters paramBlake3Parameters) {
    byte[] arrayOfByte1 = (paramBlake3Parameters == null) ? null : paramBlake3Parameters.getKey();
    byte[] arrayOfByte2 = (paramBlake3Parameters == null) ? null : paramBlake3Parameters.getContext();
    reset();
    if (arrayOfByte1 != null) {
      initKey(arrayOfByte1);
      Arrays.fill(arrayOfByte1, (byte)0);
    } else if (arrayOfByte2 != null) {
      initNullKey();
      this.theMode = 32;
      update(arrayOfByte2, 0, arrayOfByte2.length);
      doFinal(this.theBuffer, 0);
      initKeyFromContext();
      reset();
    } else {
      initNullKey();
      this.theMode = 0;
    } 
  }
  
  public void update(byte paramByte) {
    if (this.outputting)
      throw new IllegalStateException("Already outputting"); 
    int i = this.theBuffer.length;
    int j = i - this.thePos;
    if (j == 0) {
      compressBlock(this.theBuffer, 0);
      Arrays.fill(this.theBuffer, (byte)0);
      this.thePos = 0;
    } 
    this.theBuffer[this.thePos] = paramByte;
    this.thePos++;
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (paramArrayOfbyte == null || paramInt2 == 0)
      return; 
    if (this.outputting)
      throw new IllegalStateException("Already outputting"); 
    int i = 0;
    if (this.thePos != 0) {
      i = 64 - this.thePos;
      if (i >= paramInt2) {
        System.arraycopy(paramArrayOfbyte, paramInt1, this.theBuffer, this.thePos, paramInt2);
        this.thePos += paramInt2;
        return;
      } 
      System.arraycopy(paramArrayOfbyte, paramInt1, this.theBuffer, this.thePos, i);
      compressBlock(this.theBuffer, 0);
      this.thePos = 0;
      Arrays.fill(this.theBuffer, (byte)0);
    } 
    int k = paramInt1 + paramInt2 - 64;
    int j;
    for (j = paramInt1 + i; j < k; j += 64)
      compressBlock(paramArrayOfbyte, j); 
    int m = paramInt2 - j;
    System.arraycopy(paramArrayOfbyte, j, this.theBuffer, 0, paramInt1 + m);
    this.thePos += paramInt1 + m;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    return doFinal(paramArrayOfbyte, paramInt, getDigestSize());
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.outputting)
      throw new IllegalStateException("Already outputting"); 
    int i = doOutput(paramArrayOfbyte, paramInt1, paramInt2);
    reset();
    return i;
  }
  
  public int doOutput(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (!this.outputting)
      compressFinalBlock(this.thePos); 
    if (paramInt2 < 0 || (this.outputAvailable >= 0L && paramInt2 > this.outputAvailable))
      throw new IllegalArgumentException("Insufficient bytes remaining"); 
    int i = paramInt2;
    int j = paramInt1;
    if (this.thePos < 64) {
      int k = Math.min(i, 64 - this.thePos);
      System.arraycopy(this.theBuffer, this.thePos, paramArrayOfbyte, j, k);
      this.thePos += k;
      j += k;
      i -= k;
    } 
    while (i > 0) {
      nextOutputBlock();
      int k = Math.min(i, 64);
      System.arraycopy(this.theBuffer, 0, paramArrayOfbyte, j, k);
      this.thePos += k;
      j += k;
      i -= k;
    } 
    this.outputAvailable -= paramInt2;
    return paramInt2;
  }
  
  public void reset() {
    resetBlockCount();
    this.thePos = 0;
    this.outputting = false;
    Arrays.fill(this.theBuffer, (byte)0);
  }
  
  public void reset(Memoable paramMemoable) {
    Blake3Digest blake3Digest = (Blake3Digest)paramMemoable;
    this.theCounter = blake3Digest.theCounter;
    this.theCurrBytes = blake3Digest.theCurrBytes;
    this.theMode = blake3Digest.theMode;
    this.outputting = blake3Digest.outputting;
    this.outputAvailable = blake3Digest.outputAvailable;
    this.theOutputMode = blake3Digest.theOutputMode;
    this.theOutputDataLen = blake3Digest.theOutputDataLen;
    System.arraycopy(blake3Digest.theChaining, 0, this.theChaining, 0, this.theChaining.length);
    System.arraycopy(blake3Digest.theK, 0, this.theK, 0, this.theK.length);
    System.arraycopy(blake3Digest.theM, 0, this.theM, 0, this.theM.length);
    this.theStack.clear();
    Iterator<int[]> iterator = blake3Digest.theStack.iterator();
    while (iterator.hasNext())
      this.theStack.push(Arrays.clone(iterator.next())); 
    System.arraycopy(blake3Digest.theBuffer, 0, this.theBuffer, 0, this.theBuffer.length);
    this.thePos = blake3Digest.thePos;
  }
  
  public Memoable copy() {
    return new Blake3Digest(this);
  }
  
  private void compressBlock(byte[] paramArrayOfbyte, int paramInt) {
    initChunkBlock(64, false);
    initM(paramArrayOfbyte, paramInt);
    compress();
    if (this.theCurrBytes == 0)
      adjustStack(); 
  }
  
  private void adjustStack() {
    for (long l = this.theCounter; l > 0L && (l & 0x1L) != 1L; l >>= 1L) {
      int[] arrayOfInt = this.theStack.pop();
      System.arraycopy(arrayOfInt, 0, this.theM, 0, 8);
      System.arraycopy(this.theChaining, 0, this.theM, 8, 8);
      initParentBlock();
      compress();
    } 
    this.theStack.push(Arrays.copyOf(this.theChaining, 8));
  }
  
  private void compressFinalBlock(int paramInt) {
    initChunkBlock(paramInt, true);
    initM(this.theBuffer, 0);
    compress();
    processStack();
  }
  
  private void processStack() {
    while (!this.theStack.isEmpty()) {
      int[] arrayOfInt = this.theStack.pop();
      System.arraycopy(arrayOfInt, 0, this.theM, 0, 8);
      System.arraycopy(this.theChaining, 0, this.theM, 8, 8);
      initParentBlock();
      if (this.theStack.isEmpty())
        setRoot(); 
      compress();
    } 
  }
  
  private void compress() {
    initIndices();
    for (byte b = 0; b < 6; b++) {
      performRound();
      permuteIndices();
    } 
    performRound();
    adjustChaining();
  }
  
  private void performRound() {
    byte b = 0;
    mixG(b++, 0, 4, 8, 12);
    mixG(b++, 1, 5, 9, 13);
    mixG(b++, 2, 6, 10, 14);
    mixG(b++, 3, 7, 11, 15);
    mixG(b++, 0, 5, 10, 15);
    mixG(b++, 1, 6, 11, 12);
    mixG(b++, 2, 7, 8, 13);
    mixG(b, 3, 4, 9, 14);
  }
  
  private void initM(byte[] paramArrayOfbyte, int paramInt) {
    for (byte b = 0; b < 16; b++)
      this.theM[b] = Pack.littleEndianToInt(paramArrayOfbyte, paramInt + b * 4); 
  }
  
  private void adjustChaining() {
    if (this.outputting) {
      byte b;
      for (b = 0; b < 8; b++) {
        this.theV[b] = this.theV[b] ^ this.theV[b + 8];
        this.theV[b + 8] = this.theV[b + 8] ^ this.theChaining[b];
      } 
      for (b = 0; b < 16; b++)
        Pack.intToLittleEndian(this.theV[b], this.theBuffer, b * 4); 
      this.thePos = 0;
    } else {
      for (byte b = 0; b < 8; b++)
        this.theChaining[b] = this.theV[b] ^ this.theV[b + 8]; 
    } 
  }
  
  private void mixG(int paramInt1, int paramInt2, int paramInt3, int paramInt4, int paramInt5) {
    int i = paramInt1 << 1;
    byte b = 0;
    this.theV[paramInt2] = this.theV[paramInt2] + this.theV[paramInt3] + this.theM[this.theIndices[i++]];
    this.theV[paramInt5] = Integers.rotateRight(this.theV[paramInt5] ^ this.theV[paramInt2], ROTATE[b++]);
    this.theV[paramInt4] = this.theV[paramInt4] + this.theV[paramInt5];
    this.theV[paramInt3] = Integers.rotateRight(this.theV[paramInt3] ^ this.theV[paramInt4], ROTATE[b++]);
    this.theV[paramInt2] = this.theV[paramInt2] + this.theV[paramInt3] + this.theM[this.theIndices[i]];
    this.theV[paramInt5] = Integers.rotateRight(this.theV[paramInt5] ^ this.theV[paramInt2], ROTATE[b++]);
    this.theV[paramInt4] = this.theV[paramInt4] + this.theV[paramInt5];
    this.theV[paramInt3] = Integers.rotateRight(this.theV[paramInt3] ^ this.theV[paramInt4], ROTATE[b]);
  }
  
  private void initIndices() {
    for (byte b = 0; b < this.theIndices.length; b = (byte)(b + 1))
      this.theIndices[b] = b; 
  }
  
  private void permuteIndices() {
    for (byte b = 0; b < this.theIndices.length; b = (byte)(b + 1))
      this.theIndices[b] = SIGMA[this.theIndices[b]]; 
  }
  
  private void initNullKey() {
    System.arraycopy(IV, 0, this.theK, 0, 8);
  }
  
  private void initKey(byte[] paramArrayOfbyte) {
    for (byte b = 0; b < 8; b++)
      this.theK[b] = Pack.littleEndianToInt(paramArrayOfbyte, b * 4); 
    this.theMode = 16;
  }
  
  private void initKeyFromContext() {
    System.arraycopy(this.theV, 0, this.theK, 0, 8);
    this.theMode = 64;
  }
  
  private void initChunkBlock(int paramInt, boolean paramBoolean) {
    System.arraycopy((this.theCurrBytes == 0) ? this.theK : this.theChaining, 0, this.theV, 0, 8);
    System.arraycopy(IV, 0, this.theV, 8, 4);
    this.theV[12] = (int)this.theCounter;
    this.theV[13] = (int)(this.theCounter >> 32L);
    this.theV[14] = paramInt;
    this.theV[15] = this.theMode + ((this.theCurrBytes == 0) ? 1 : 0) + (paramBoolean ? 2 : 0);
    this.theCurrBytes += paramInt;
    if (this.theCurrBytes >= 1024) {
      incrementBlockCount();
      this.theV[15] = this.theV[15] | 0x2;
    } 
    if (paramBoolean && this.theStack.isEmpty())
      setRoot(); 
  }
  
  private void initParentBlock() {
    System.arraycopy(this.theK, 0, this.theV, 0, 8);
    System.arraycopy(IV, 0, this.theV, 8, 4);
    this.theV[12] = 0;
    this.theV[13] = 0;
    this.theV[14] = 64;
    this.theV[15] = this.theMode | 0x4;
  }
  
  private void nextOutputBlock() {
    this.theCounter++;
    System.arraycopy(this.theChaining, 0, this.theV, 0, 8);
    System.arraycopy(IV, 0, this.theV, 8, 4);
    this.theV[12] = (int)this.theCounter;
    this.theV[13] = (int)(this.theCounter >> 32L);
    this.theV[14] = this.theOutputDataLen;
    this.theV[15] = this.theOutputMode;
    compress();
  }
  
  private void incrementBlockCount() {
    this.theCounter++;
    this.theCurrBytes = 0;
  }
  
  private void resetBlockCount() {
    this.theCounter = 0L;
    this.theCurrBytes = 0;
  }
  
  private void setRoot() {
    this.theV[15] = this.theV[15] | 0x8;
    this.theOutputMode = this.theV[15];
    this.theOutputDataLen = this.theV[14];
    this.theCounter = 0L;
    this.outputting = true;
    this.outputAvailable = -1L;
    System.arraycopy(this.theV, 0, this.theChaining, 0, 8);
  }
}
