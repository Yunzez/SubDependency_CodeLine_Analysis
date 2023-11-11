package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

public class NoekeonEngine implements BlockCipher {
  private static final int SIZE = 16;
  
  private static final byte[] roundConstants = new byte[] { 
      Byte.MIN_VALUE, 27, 54, 108, -40, -85, 77, -102, 47, 94, 
      -68, 99, -58, -105, 53, 106, -44 };
  
  private final int[] k = new int[4];
  
  private boolean _initialised = false;
  
  private boolean _forEncryption;
  
  public String getAlgorithmName() {
    return "Noekeon";
  }
  
  public int getBlockSize() {
    return 16;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    if (!(paramCipherParameters instanceof KeyParameter))
      throw new IllegalArgumentException("invalid parameter passed to Noekeon init - " + paramCipherParameters.getClass().getName()); 
    KeyParameter keyParameter = (KeyParameter)paramCipherParameters;
    byte[] arrayOfByte = keyParameter.getKey();
    if (arrayOfByte.length != 16)
      throw new IllegalArgumentException("Key length not 128 bits."); 
    Pack.bigEndianToInt(arrayOfByte, 0, this.k, 0, 4);
    if (!paramBoolean) {
      int i = this.k[0];
      int j = this.k[1];
      int k = this.k[2];
      int m = this.k[3];
      int n = i ^ k;
      n ^= Integers.rotateLeft(n, 8) ^ Integers.rotateLeft(n, 24);
      int i1 = j ^ m;
      i1 ^= Integers.rotateLeft(i1, 8) ^ Integers.rotateLeft(i1, 24);
      i ^= i1;
      j ^= n;
      k ^= i1;
      m ^= n;
      this.k[0] = i;
      this.k[1] = j;
      this.k[2] = k;
      this.k[3] = m;
    } 
    this._forEncryption = paramBoolean;
    this._initialised = true;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    if (!this._initialised)
      throw new IllegalStateException(getAlgorithmName() + " not initialised"); 
    if (paramInt1 > paramArrayOfbyte1.length - 16)
      throw new DataLengthException("input buffer too short"); 
    if (paramInt2 > paramArrayOfbyte2.length - 16)
      throw new OutputLengthException("output buffer too short"); 
    return this._forEncryption ? encryptBlock(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2) : decryptBlock(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2);
  }
  
  public void reset() {}
  
  private int encryptBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    int i = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1);
    int j = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1 + 4);
    int k = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1 + 8);
    int m = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1 + 12);
    int n = this.k[0];
    int i1 = this.k[1];
    int i2 = this.k[2];
    int i3 = this.k[3];
    byte b = 0;
    while (true) {
      i ^= roundConstants[b] & 0xFF;
      int i4 = i ^ k;
      i4 ^= Integers.rotateLeft(i4, 8) ^ Integers.rotateLeft(i4, 24);
      i ^= n;
      j ^= i1;
      k ^= i2;
      m ^= i3;
      int i5 = j ^ m;
      i5 ^= Integers.rotateLeft(i5, 8) ^ Integers.rotateLeft(i5, 24);
      i ^= i5;
      j ^= i4;
      k ^= i5;
      m ^= i4;
      if (++b > 16) {
        Pack.intToBigEndian(i, paramArrayOfbyte2, paramInt2);
        Pack.intToBigEndian(j, paramArrayOfbyte2, paramInt2 + 4);
        Pack.intToBigEndian(k, paramArrayOfbyte2, paramInt2 + 8);
        Pack.intToBigEndian(m, paramArrayOfbyte2, paramInt2 + 12);
        return 16;
      } 
      j = Integers.rotateLeft(j, 1);
      k = Integers.rotateLeft(k, 5);
      m = Integers.rotateLeft(m, 2);
      i4 = m;
      j ^= m | k;
      m = i ^ k & (j ^ 0xFFFFFFFF);
      k = i4 ^ j ^ 0xFFFFFFFF ^ k ^ m;
      j ^= m | k;
      i = i4 ^ k & j;
      j = Integers.rotateLeft(j, 31);
      k = Integers.rotateLeft(k, 27);
      m = Integers.rotateLeft(m, 30);
    } 
  }
  
  private int decryptBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    int i = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1);
    int j = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1 + 4);
    int k = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1 + 8);
    int m = Pack.bigEndianToInt(paramArrayOfbyte1, paramInt1 + 12);
    int n = this.k[0];
    int i1 = this.k[1];
    int i2 = this.k[2];
    int i3 = this.k[3];
    byte b = 16;
    while (true) {
      int i4 = i ^ k;
      i4 ^= Integers.rotateLeft(i4, 8) ^ Integers.rotateLeft(i4, 24);
      i ^= n;
      j ^= i1;
      k ^= i2;
      m ^= i3;
      int i5 = j ^ m;
      i5 ^= Integers.rotateLeft(i5, 8) ^ Integers.rotateLeft(i5, 24);
      i ^= i5;
      j ^= i4;
      k ^= i5;
      m ^= i4;
      i ^= roundConstants[b] & 0xFF;
      if (--b < 0) {
        Pack.intToBigEndian(i, paramArrayOfbyte2, paramInt2);
        Pack.intToBigEndian(j, paramArrayOfbyte2, paramInt2 + 4);
        Pack.intToBigEndian(k, paramArrayOfbyte2, paramInt2 + 8);
        Pack.intToBigEndian(m, paramArrayOfbyte2, paramInt2 + 12);
        return 16;
      } 
      j = Integers.rotateLeft(j, 1);
      k = Integers.rotateLeft(k, 5);
      m = Integers.rotateLeft(m, 2);
      i4 = m;
      j ^= m | k;
      m = i ^ k & (j ^ 0xFFFFFFFF);
      k = i4 ^ j ^ 0xFFFFFFFF ^ k ^ m;
      j ^= m | k;
      i = i4 ^ k & j;
      j = Integers.rotateLeft(j, 31);
      k = Integers.rotateLeft(k, 27);
      m = Integers.rotateLeft(m, 30);
    } 
  }
}
