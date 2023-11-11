package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class Blake2sDigest implements ExtendedDigest {
  private static final int[] blake2s_IV = new int[] { 1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225 };
  
  private static final byte[][] blake2s_sigma = new byte[][] { { 
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 
        10, 11, 12, 13, 14, 15 }, { 
        14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 
        0, 2, 11, 7, 5, 3 }, { 
        11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 
        3, 6, 7, 1, 9, 4 }, { 
        7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 
        5, 10, 4, 0, 15, 8 }, { 
        9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 
        11, 12, 6, 8, 3, 13 }, { 
        2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 
        7, 5, 15, 14, 1, 9 }, { 
        12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 
        6, 3, 9, 2, 8, 11 }, { 
        13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 
        15, 4, 8, 6, 2, 10 }, { 
        6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 
        13, 7, 1, 4, 10, 5 }, { 
        10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 
        9, 14, 3, 12, 13, 0 } };
  
  private static final int ROUNDS = 10;
  
  private static final int BLOCK_LENGTH_BYTES = 64;
  
  private int digestLength = 32;
  
  private int keyLength = 0;
  
  private byte[] salt = null;
  
  private byte[] personalization = null;
  
  private byte[] key = null;
  
  private int fanout = 1;
  
  private int depth = 1;
  
  private int leafLength = 0;
  
  private long nodeOffset = 0L;
  
  private int nodeDepth = 0;
  
  private int innerHashLength = 0;
  
  private byte[] buffer = null;
  
  private int bufferPos = 0;
  
  private int[] internalState = new int[16];
  
  private int[] chainValue = null;
  
  private int t0 = 0;
  
  private int t1 = 0;
  
  private int f0 = 0;
  
  public Blake2sDigest() {
    this(256);
  }
  
  public Blake2sDigest(Blake2sDigest paramBlake2sDigest) {
    this.bufferPos = paramBlake2sDigest.bufferPos;
    this.buffer = Arrays.clone(paramBlake2sDigest.buffer);
    this.keyLength = paramBlake2sDigest.keyLength;
    this.key = Arrays.clone(paramBlake2sDigest.key);
    this.digestLength = paramBlake2sDigest.digestLength;
    this.internalState = Arrays.clone(this.internalState);
    this.chainValue = Arrays.clone(paramBlake2sDigest.chainValue);
    this.t0 = paramBlake2sDigest.t0;
    this.t1 = paramBlake2sDigest.t1;
    this.f0 = paramBlake2sDigest.f0;
    this.salt = Arrays.clone(paramBlake2sDigest.salt);
    this.personalization = Arrays.clone(paramBlake2sDigest.personalization);
    this.fanout = paramBlake2sDigest.fanout;
    this.depth = paramBlake2sDigest.depth;
    this.leafLength = paramBlake2sDigest.leafLength;
    this.nodeOffset = paramBlake2sDigest.nodeOffset;
    this.nodeDepth = paramBlake2sDigest.nodeDepth;
    this.innerHashLength = paramBlake2sDigest.innerHashLength;
  }
  
  public Blake2sDigest(int paramInt) {
    if (paramInt < 8 || paramInt > 256 || paramInt % 8 != 0)
      throw new IllegalArgumentException("BLAKE2s digest bit length must be a multiple of 8 and not greater than 256"); 
    this.digestLength = paramInt / 8;
    init(null, null, null);
  }
  
  public Blake2sDigest(byte[] paramArrayOfbyte) {
    init(null, null, paramArrayOfbyte);
  }
  
  public Blake2sDigest(byte[] paramArrayOfbyte1, int paramInt, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    if (paramInt < 1 || paramInt > 32)
      throw new IllegalArgumentException("Invalid digest length (required: 1 - 32)"); 
    this.digestLength = paramInt;
    init(paramArrayOfbyte2, paramArrayOfbyte3, paramArrayOfbyte1);
  }
  
  Blake2sDigest(int paramInt, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, long paramLong) {
    this.digestLength = paramInt;
    this.nodeOffset = paramLong;
    init(paramArrayOfbyte2, paramArrayOfbyte3, paramArrayOfbyte1);
  }
  
  Blake2sDigest(int paramInt1, int paramInt2, long paramLong) {
    this.digestLength = paramInt1;
    this.nodeOffset = paramLong;
    this.fanout = 0;
    this.depth = 0;
    this.leafLength = paramInt2;
    this.innerHashLength = paramInt2;
    this.nodeDepth = 0;
    init(null, null, null);
  }
  
  private void init(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3) {
    this.buffer = new byte[64];
    if (paramArrayOfbyte3 != null && paramArrayOfbyte3.length > 0) {
      if (paramArrayOfbyte3.length > 32)
        throw new IllegalArgumentException("Keys > 32 bytes are not supported"); 
      this.key = new byte[paramArrayOfbyte3.length];
      System.arraycopy(paramArrayOfbyte3, 0, this.key, 0, paramArrayOfbyte3.length);
      this.keyLength = paramArrayOfbyte3.length;
      System.arraycopy(paramArrayOfbyte3, 0, this.buffer, 0, paramArrayOfbyte3.length);
      this.bufferPos = 64;
    } 
    if (this.chainValue == null) {
      this.chainValue = new int[8];
      this.chainValue[0] = blake2s_IV[0] ^ (this.digestLength | this.keyLength << 8 | this.fanout << 16 | this.depth << 24);
      this.chainValue[1] = blake2s_IV[1] ^ this.leafLength;
      int i = (int)(this.nodeOffset >> 32L);
      int j = (int)this.nodeOffset;
      this.chainValue[2] = blake2s_IV[2] ^ j;
      this.chainValue[3] = blake2s_IV[3] ^ (i | this.nodeDepth << 16 | this.innerHashLength << 24);
      this.chainValue[4] = blake2s_IV[4];
      this.chainValue[5] = blake2s_IV[5];
      if (paramArrayOfbyte1 != null) {
        if (paramArrayOfbyte1.length != 8)
          throw new IllegalArgumentException("Salt length must be exactly 8 bytes"); 
        this.salt = new byte[8];
        System.arraycopy(paramArrayOfbyte1, 0, this.salt, 0, paramArrayOfbyte1.length);
        this.chainValue[4] = this.chainValue[4] ^ Pack.littleEndianToInt(paramArrayOfbyte1, 0);
        this.chainValue[5] = this.chainValue[5] ^ Pack.littleEndianToInt(paramArrayOfbyte1, 4);
      } 
      this.chainValue[6] = blake2s_IV[6];
      this.chainValue[7] = blake2s_IV[7];
      if (paramArrayOfbyte2 != null) {
        if (paramArrayOfbyte2.length != 8)
          throw new IllegalArgumentException("Personalization length must be exactly 8 bytes"); 
        this.personalization = new byte[8];
        System.arraycopy(paramArrayOfbyte2, 0, this.personalization, 0, paramArrayOfbyte2.length);
        this.chainValue[6] = this.chainValue[6] ^ Pack.littleEndianToInt(paramArrayOfbyte2, 0);
        this.chainValue[7] = this.chainValue[7] ^ Pack.littleEndianToInt(paramArrayOfbyte2, 4);
      } 
    } 
  }
  
  private void initializeInternalState() {
    System.arraycopy(this.chainValue, 0, this.internalState, 0, this.chainValue.length);
    System.arraycopy(blake2s_IV, 0, this.internalState, this.chainValue.length, 4);
    this.internalState[12] = this.t0 ^ blake2s_IV[4];
    this.internalState[13] = this.t1 ^ blake2s_IV[5];
    this.internalState[14] = this.f0 ^ blake2s_IV[6];
    this.internalState[15] = blake2s_IV[7];
  }
  
  public void update(byte paramByte) {
    int i = 64 - this.bufferPos;
    if (i == 0) {
      this.t0 += 64;
      if (this.t0 == 0)
        this.t1++; 
      compress(this.buffer, 0);
      Arrays.fill(this.buffer, (byte)0);
      this.buffer[0] = paramByte;
      this.bufferPos = 1;
    } else {
      this.buffer[this.bufferPos] = paramByte;
      this.bufferPos++;
    } 
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (paramArrayOfbyte == null || paramInt2 == 0)
      return; 
    int i = 0;
    if (this.bufferPos != 0) {
      i = 64 - this.bufferPos;
      if (i < paramInt2) {
        System.arraycopy(paramArrayOfbyte, paramInt1, this.buffer, this.bufferPos, i);
        this.t0 += 64;
        if (this.t0 == 0)
          this.t1++; 
        compress(this.buffer, 0);
        this.bufferPos = 0;
        Arrays.fill(this.buffer, (byte)0);
      } else {
        System.arraycopy(paramArrayOfbyte, paramInt1, this.buffer, this.bufferPos, paramInt2);
        this.bufferPos += paramInt2;
        return;
      } 
    } 
    int k = paramInt1 + paramInt2 - 64;
    int j;
    for (j = paramInt1 + i; j < k; j += 64) {
      this.t0 += 64;
      if (this.t0 == 0)
        this.t1++; 
      compress(paramArrayOfbyte, j);
    } 
    System.arraycopy(paramArrayOfbyte, j, this.buffer, 0, paramInt1 + paramInt2 - j);
    this.bufferPos += paramInt1 + paramInt2 - j;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    this.f0 = -1;
    this.t0 += this.bufferPos;
    if (this.t0 < 0 && this.bufferPos > -this.t0)
      this.t1++; 
    compress(this.buffer, 0);
    Arrays.fill(this.buffer, (byte)0);
    Arrays.fill(this.internalState, 0);
    for (byte b = 0; b < this.chainValue.length && b * 4 < this.digestLength; b++) {
      byte[] arrayOfByte = Pack.intToLittleEndian(this.chainValue[b]);
      if (b * 4 < this.digestLength - 4) {
        System.arraycopy(arrayOfByte, 0, paramArrayOfbyte, paramInt + b * 4, 4);
      } else {
        System.arraycopy(arrayOfByte, 0, paramArrayOfbyte, paramInt + b * 4, this.digestLength - b * 4);
      } 
    } 
    Arrays.fill(this.chainValue, 0);
    reset();
    return this.digestLength;
  }
  
  public void reset() {
    this.bufferPos = 0;
    this.f0 = 0;
    this.t0 = 0;
    this.t1 = 0;
    this.chainValue = null;
    Arrays.fill(this.buffer, (byte)0);
    if (this.key != null) {
      System.arraycopy(this.key, 0, this.buffer, 0, this.key.length);
      this.bufferPos = 64;
    } 
    init(this.salt, this.personalization, this.key);
  }
  
  private void compress(byte[] paramArrayOfbyte, int paramInt) {
    initializeInternalState();
    int[] arrayOfInt = new int[16];
    byte b;
    for (b = 0; b < 16; b++)
      arrayOfInt[b] = Pack.littleEndianToInt(paramArrayOfbyte, paramInt + b * 4); 
    for (b = 0; b < 10; b++) {
      G(arrayOfInt[blake2s_sigma[b][0]], arrayOfInt[blake2s_sigma[b][1]], 0, 4, 8, 12);
      G(arrayOfInt[blake2s_sigma[b][2]], arrayOfInt[blake2s_sigma[b][3]], 1, 5, 9, 13);
      G(arrayOfInt[blake2s_sigma[b][4]], arrayOfInt[blake2s_sigma[b][5]], 2, 6, 10, 14);
      G(arrayOfInt[blake2s_sigma[b][6]], arrayOfInt[blake2s_sigma[b][7]], 3, 7, 11, 15);
      G(arrayOfInt[blake2s_sigma[b][8]], arrayOfInt[blake2s_sigma[b][9]], 0, 5, 10, 15);
      G(arrayOfInt[blake2s_sigma[b][10]], arrayOfInt[blake2s_sigma[b][11]], 1, 6, 11, 12);
      G(arrayOfInt[blake2s_sigma[b][12]], arrayOfInt[blake2s_sigma[b][13]], 2, 7, 8, 13);
      G(arrayOfInt[blake2s_sigma[b][14]], arrayOfInt[blake2s_sigma[b][15]], 3, 4, 9, 14);
    } 
    for (b = 0; b < this.chainValue.length; b++)
      this.chainValue[b] = this.chainValue[b] ^ this.internalState[b] ^ this.internalState[b + 8]; 
  }
  
  private void G(int paramInt1, int paramInt2, int paramInt3, int paramInt4, int paramInt5, int paramInt6) {
    this.internalState[paramInt3] = this.internalState[paramInt3] + this.internalState[paramInt4] + paramInt1;
    this.internalState[paramInt6] = rotr32(this.internalState[paramInt6] ^ this.internalState[paramInt3], 16);
    this.internalState[paramInt5] = this.internalState[paramInt5] + this.internalState[paramInt6];
    this.internalState[paramInt4] = rotr32(this.internalState[paramInt4] ^ this.internalState[paramInt5], 12);
    this.internalState[paramInt3] = this.internalState[paramInt3] + this.internalState[paramInt4] + paramInt2;
    this.internalState[paramInt6] = rotr32(this.internalState[paramInt6] ^ this.internalState[paramInt3], 8);
    this.internalState[paramInt5] = this.internalState[paramInt5] + this.internalState[paramInt6];
    this.internalState[paramInt4] = rotr32(this.internalState[paramInt4] ^ this.internalState[paramInt5], 7);
  }
  
  private int rotr32(int paramInt1, int paramInt2) {
    return paramInt1 >>> paramInt2 | paramInt1 << 32 - paramInt2;
  }
  
  public String getAlgorithmName() {
    return "BLAKE2s";
  }
  
  public int getDigestSize() {
    return this.digestLength;
  }
  
  public int getByteLength() {
    return 64;
  }
  
  public void clearKey() {
    if (this.key != null) {
      Arrays.fill(this.key, (byte)0);
      Arrays.fill(this.buffer, (byte)0);
    } 
  }
  
  public void clearSalt() {
    if (this.salt != null)
      Arrays.fill(this.salt, (byte)0); 
  }
}
