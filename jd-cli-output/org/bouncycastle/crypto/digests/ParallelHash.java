package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class ParallelHash implements Xof, Digest {
  private static final byte[] N_PARALLEL_HASH = Strings.toByteArray("ParallelHash");
  
  private final CSHAKEDigest cshake;
  
  private final CSHAKEDigest compressor;
  
  private final int bitLength;
  
  private final int outputLength;
  
  private final int B;
  
  private final byte[] buffer;
  
  private final byte[] compressorBuffer;
  
  private boolean firstOutput;
  
  private int nCount;
  
  private int bufOff;
  
  public ParallelHash(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    this(paramInt1, paramArrayOfbyte, paramInt2, paramInt1 * 2);
  }
  
  public ParallelHash(int paramInt1, byte[] paramArrayOfbyte, int paramInt2, int paramInt3) {
    this.cshake = new CSHAKEDigest(paramInt1, N_PARALLEL_HASH, paramArrayOfbyte);
    this.compressor = new CSHAKEDigest(paramInt1, new byte[0], new byte[0]);
    this.bitLength = paramInt1;
    this.B = paramInt2;
    this.outputLength = (paramInt3 + 7) / 8;
    this.buffer = new byte[paramInt2];
    this.compressorBuffer = new byte[paramInt1 * 2 / 8];
    reset();
  }
  
  public ParallelHash(ParallelHash paramParallelHash) {
    this.cshake = new CSHAKEDigest(paramParallelHash.cshake);
    this.compressor = new CSHAKEDigest(paramParallelHash.compressor);
    this.bitLength = paramParallelHash.bitLength;
    this.B = paramParallelHash.B;
    this.outputLength = paramParallelHash.outputLength;
    this.buffer = Arrays.clone(paramParallelHash.buffer);
    this.compressorBuffer = Arrays.clone(paramParallelHash.compressorBuffer);
  }
  
  public String getAlgorithmName() {
    return "ParallelHash" + this.cshake.getAlgorithmName().substring(6);
  }
  
  public int getByteLength() {
    return this.cshake.getByteLength();
  }
  
  public int getDigestSize() {
    return this.outputLength;
  }
  
  public void update(byte paramByte) throws IllegalStateException {
    this.buffer[this.bufOff++] = paramByte;
    if (this.bufOff == this.buffer.length)
      compress(); 
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws DataLengthException, IllegalStateException {
    paramInt2 = Math.max(0, paramInt2);
    int i = 0;
    if (this.bufOff != 0) {
      while (i < paramInt2 && this.bufOff != this.buffer.length)
        this.buffer[this.bufOff++] = paramArrayOfbyte[paramInt1 + i++]; 
      if (this.bufOff == this.buffer.length)
        compress(); 
    } 
    if (i < paramInt2)
      while (paramInt2 - i > this.B) {
        compress(paramArrayOfbyte, paramInt1 + i, this.B);
        i += this.B;
      }  
    while (i < paramInt2)
      update(paramArrayOfbyte[paramInt1 + i++]); 
  }
  
  private void compress() {
    compress(this.buffer, 0, this.bufOff);
    this.bufOff = 0;
  }
  
  private void compress(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.compressor.update(paramArrayOfbyte, paramInt1, paramInt2);
    this.compressor.doFinal(this.compressorBuffer, 0, this.compressorBuffer.length);
    this.cshake.update(this.compressorBuffer, 0, this.compressorBuffer.length);
    this.nCount++;
  }
  
  private void wrapUp(int paramInt) {
    if (this.bufOff != 0)
      compress(); 
    byte[] arrayOfByte1 = XofUtils.rightEncode(this.nCount);
    byte[] arrayOfByte2 = XofUtils.rightEncode((paramInt * 8));
    this.cshake.update(arrayOfByte1, 0, arrayOfByte1.length);
    this.cshake.update(arrayOfByte2, 0, arrayOfByte2.length);
    this.firstOutput = false;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) throws DataLengthException, IllegalStateException {
    if (this.firstOutput)
      wrapUp(this.outputLength); 
    int i = this.cshake.doFinal(paramArrayOfbyte, paramInt, getDigestSize());
    reset();
    return i;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.firstOutput)
      wrapUp(this.outputLength); 
    int i = this.cshake.doFinal(paramArrayOfbyte, paramInt1, paramInt2);
    reset();
    return i;
  }
  
  public int doOutput(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.firstOutput)
      wrapUp(0); 
    return this.cshake.doOutput(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public void reset() {
    this.cshake.reset();
    Arrays.clear(this.buffer);
    byte[] arrayOfByte = XofUtils.leftEncode(this.B);
    this.cshake.update(arrayOfByte, 0, arrayOfByte.length);
    this.nCount = 0;
    this.bufOff = 0;
    this.firstOutput = true;
  }
}
