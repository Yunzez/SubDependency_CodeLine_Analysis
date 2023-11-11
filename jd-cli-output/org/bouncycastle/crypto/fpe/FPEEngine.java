package org.bouncycastle.crypto.fpe;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.util.Pack;

public abstract class FPEEngine {
  protected final BlockCipher baseCipher;
  
  protected boolean forEncryption;
  
  protected FPEParameters fpeParameters;
  
  protected FPEEngine(BlockCipher paramBlockCipher) {
    this.baseCipher = paramBlockCipher;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    if (this.fpeParameters == null)
      throw new IllegalStateException("FPE engine not initialized"); 
    if (paramInt2 < 0)
      throw new IllegalArgumentException("input length cannot be negative"); 
    if (paramArrayOfbyte1 == null || paramArrayOfbyte2 == null)
      throw new NullPointerException("buffer value is null"); 
    if (paramArrayOfbyte1.length < paramInt1 + paramInt2)
      throw new DataLengthException("input buffer too short"); 
    if (paramArrayOfbyte2.length < paramInt3 + paramInt2)
      throw new OutputLengthException("output buffer too short"); 
    return this.forEncryption ? encryptBlock(paramArrayOfbyte1, paramInt1, paramInt2, paramArrayOfbyte2, paramInt3) : decryptBlock(paramArrayOfbyte1, paramInt1, paramInt2, paramArrayOfbyte2, paramInt3);
  }
  
  protected static short[] toShortArray(byte[] paramArrayOfbyte) {
    if ((paramArrayOfbyte.length & 0x1) != 0)
      throw new IllegalArgumentException("data must be an even number of bytes for a wide radix"); 
    short[] arrayOfShort = new short[paramArrayOfbyte.length / 2];
    for (byte b = 0; b != arrayOfShort.length; b++)
      arrayOfShort[b] = Pack.bigEndianToShort(paramArrayOfbyte, b * 2); 
    return arrayOfShort;
  }
  
  protected static byte[] toByteArray(short[] paramArrayOfshort) {
    byte[] arrayOfByte = new byte[paramArrayOfshort.length * 2];
    for (byte b = 0; b != paramArrayOfshort.length; b++)
      Pack.shortToBigEndian(paramArrayOfshort[b], arrayOfByte, b * 2); 
    return arrayOfByte;
  }
  
  public abstract void init(boolean paramBoolean, CipherParameters paramCipherParameters);
  
  public abstract String getAlgorithmName();
  
  protected abstract int encryptBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3);
  
  protected abstract int decryptBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3);
}
