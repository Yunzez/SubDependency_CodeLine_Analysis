package org.bouncycastle.crypto.digests;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Strings;

public class TupleHash implements Xof, Digest {
  private static final byte[] N_TUPLE_HASH = Strings.toByteArray("TupleHash");
  
  private final CSHAKEDigest cshake;
  
  private final int bitLength;
  
  private final int outputLength;
  
  private boolean firstOutput;
  
  public TupleHash(int paramInt, byte[] paramArrayOfbyte) {
    this(paramInt, paramArrayOfbyte, paramInt * 2);
  }
  
  public TupleHash(int paramInt1, byte[] paramArrayOfbyte, int paramInt2) {
    this.cshake = new CSHAKEDigest(paramInt1, N_TUPLE_HASH, paramArrayOfbyte);
    this.bitLength = paramInt1;
    this.outputLength = (paramInt2 + 7) / 8;
    reset();
  }
  
  public TupleHash(TupleHash paramTupleHash) {
    this.cshake = new CSHAKEDigest(paramTupleHash.cshake);
    this.bitLength = this.cshake.fixedOutputLength;
    this.outputLength = this.bitLength * 2 / 8;
    this.firstOutput = paramTupleHash.firstOutput;
  }
  
  public String getAlgorithmName() {
    return "TupleHash" + this.cshake.getAlgorithmName().substring(6);
  }
  
  public int getByteLength() {
    return this.cshake.getByteLength();
  }
  
  public int getDigestSize() {
    return this.outputLength;
  }
  
  public void update(byte paramByte) throws IllegalStateException {
    byte[] arrayOfByte = XofUtils.encode(paramByte);
    this.cshake.update(arrayOfByte, 0, arrayOfByte.length);
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws DataLengthException, IllegalStateException {
    byte[] arrayOfByte = XofUtils.encode(paramArrayOfbyte, paramInt1, paramInt2);
    this.cshake.update(arrayOfByte, 0, arrayOfByte.length);
  }
  
  private void wrapUp(int paramInt) {
    byte[] arrayOfByte = XofUtils.rightEncode(paramInt * 8L);
    this.cshake.update(arrayOfByte, 0, arrayOfByte.length);
    this.firstOutput = false;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) throws DataLengthException, IllegalStateException {
    if (this.firstOutput)
      wrapUp(getDigestSize()); 
    int i = this.cshake.doFinal(paramArrayOfbyte, paramInt, getDigestSize());
    reset();
    return i;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (this.firstOutput)
      wrapUp(getDigestSize()); 
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
    this.firstOutput = true;
  }
}
