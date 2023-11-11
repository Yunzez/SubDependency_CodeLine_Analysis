package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class G3413CBCBlockCipher implements BlockCipher {
  private int m;
  
  private int blockSize;
  
  private byte[] R;
  
  private byte[] R_init;
  
  private BlockCipher cipher;
  
  private boolean initialized = false;
  
  private boolean forEncryption;
  
  public G3413CBCBlockCipher(BlockCipher paramBlockCipher) {
    this.blockSize = paramBlockCipher.getBlockSize();
    this.cipher = paramBlockCipher;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) throws IllegalArgumentException {
    this.forEncryption = paramBoolean;
    if (paramCipherParameters instanceof ParametersWithIV) {
      ParametersWithIV parametersWithIV = (ParametersWithIV)paramCipherParameters;
      byte[] arrayOfByte = parametersWithIV.getIV();
      if (arrayOfByte.length < this.blockSize)
        throw new IllegalArgumentException("Parameter m must blockSize <= m"); 
      this.m = arrayOfByte.length;
      initArrays();
      this.R_init = Arrays.clone(arrayOfByte);
      System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
      if (parametersWithIV.getParameters() != null)
        this.cipher.init(paramBoolean, parametersWithIV.getParameters()); 
    } else {
      setupDefaultParams();
      initArrays();
      System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
      if (paramCipherParameters != null)
        this.cipher.init(paramBoolean, paramCipherParameters); 
    } 
    this.initialized = true;
  }
  
  private void initArrays() {
    this.R = new byte[this.m];
    this.R_init = new byte[this.m];
  }
  
  private void setupDefaultParams() {
    this.m = this.blockSize;
  }
  
  public String getAlgorithmName() {
    return this.cipher.getAlgorithmName() + "/CBC";
  }
  
  public int getBlockSize() {
    return this.blockSize;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) throws DataLengthException, IllegalStateException {
    return this.forEncryption ? encrypt(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2) : decrypt(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt2);
  }
  
  private int encrypt(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    byte[] arrayOfByte1 = GOST3413CipherUtil.MSB(this.R, this.blockSize);
    byte[] arrayOfByte2 = GOST3413CipherUtil.copyFromInput(paramArrayOfbyte1, this.blockSize, paramInt1);
    byte[] arrayOfByte3 = GOST3413CipherUtil.sum(arrayOfByte2, arrayOfByte1);
    byte[] arrayOfByte4 = new byte[arrayOfByte3.length];
    this.cipher.processBlock(arrayOfByte3, 0, arrayOfByte4, 0);
    System.arraycopy(arrayOfByte4, 0, paramArrayOfbyte2, paramInt2, arrayOfByte4.length);
    if (paramArrayOfbyte2.length > paramInt2 + arrayOfByte3.length)
      generateR(arrayOfByte4); 
    return arrayOfByte4.length;
  }
  
  private int decrypt(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) {
    byte[] arrayOfByte1 = GOST3413CipherUtil.MSB(this.R, this.blockSize);
    byte[] arrayOfByte2 = GOST3413CipherUtil.copyFromInput(paramArrayOfbyte1, this.blockSize, paramInt1);
    byte[] arrayOfByte3 = new byte[arrayOfByte2.length];
    this.cipher.processBlock(arrayOfByte2, 0, arrayOfByte3, 0);
    byte[] arrayOfByte4 = GOST3413CipherUtil.sum(arrayOfByte3, arrayOfByte1);
    System.arraycopy(arrayOfByte4, 0, paramArrayOfbyte2, paramInt2, arrayOfByte4.length);
    if (paramArrayOfbyte2.length > paramInt2 + arrayOfByte4.length)
      generateR(arrayOfByte2); 
    return arrayOfByte4.length;
  }
  
  private void generateR(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = GOST3413CipherUtil.LSB(this.R, this.m - this.blockSize);
    System.arraycopy(arrayOfByte, 0, this.R, 0, arrayOfByte.length);
    System.arraycopy(paramArrayOfbyte, 0, this.R, arrayOfByte.length, this.m - arrayOfByte.length);
  }
  
  public void reset() {
    if (this.initialized) {
      System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
      this.cipher.reset();
    } 
  }
}
