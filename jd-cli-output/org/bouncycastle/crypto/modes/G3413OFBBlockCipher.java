package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class G3413OFBBlockCipher extends StreamBlockCipher {
  private int m;
  
  private int blockSize;
  
  private byte[] R;
  
  private byte[] R_init;
  
  private byte[] Y;
  
  private BlockCipher cipher;
  
  private int byteCount;
  
  private boolean initialized = false;
  
  public G3413OFBBlockCipher(BlockCipher paramBlockCipher) {
    super(paramBlockCipher);
    this.blockSize = paramBlockCipher.getBlockSize();
    this.cipher = paramBlockCipher;
    this.Y = new byte[this.blockSize];
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) throws IllegalArgumentException {
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
        this.cipher.init(true, parametersWithIV.getParameters()); 
    } else {
      setupDefaultParams();
      initArrays();
      System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
      if (paramCipherParameters != null)
        this.cipher.init(true, paramCipherParameters); 
    } 
    this.initialized = true;
  }
  
  private void initArrays() {
    this.R = new byte[this.m];
    this.R_init = new byte[this.m];
  }
  
  private void setupDefaultParams() {
    this.m = 2 * this.blockSize;
  }
  
  public String getAlgorithmName() {
    return this.cipher.getAlgorithmName() + "/OFB";
  }
  
  public int getBlockSize() {
    return this.blockSize;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) throws DataLengthException, IllegalStateException {
    processBytes(paramArrayOfbyte1, paramInt1, this.blockSize, paramArrayOfbyte2, paramInt2);
    return this.blockSize;
  }
  
  protected byte calculateByte(byte paramByte) {
    if (this.byteCount == 0)
      generateY(); 
    byte b = (byte)(this.Y[this.byteCount] ^ paramByte);
    this.byteCount++;
    if (this.byteCount == getBlockSize()) {
      this.byteCount = 0;
      generateR();
    } 
    return b;
  }
  
  private void generateY() {
    byte[] arrayOfByte = GOST3413CipherUtil.MSB(this.R, this.blockSize);
    this.cipher.processBlock(arrayOfByte, 0, this.Y, 0);
  }
  
  private void generateR() {
    byte[] arrayOfByte = GOST3413CipherUtil.LSB(this.R, this.m - this.blockSize);
    System.arraycopy(arrayOfByte, 0, this.R, 0, arrayOfByte.length);
    System.arraycopy(this.Y, 0, this.R, arrayOfByte.length, this.m - arrayOfByte.length);
  }
  
  public void reset() {
    if (this.initialized) {
      System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
      Arrays.clear(this.Y);
      this.byteCount = 0;
      this.cipher.reset();
    } 
  }
}
