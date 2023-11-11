package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class G3413CFBBlockCipher extends StreamBlockCipher {
  private final int s;
  
  private int m;
  
  private int blockSize;
  
  private byte[] R;
  
  private byte[] R_init;
  
  private BlockCipher cipher;
  
  private boolean forEncryption;
  
  private boolean initialized = false;
  
  private byte[] gamma;
  
  private byte[] inBuf;
  
  private int byteCount;
  
  public G3413CFBBlockCipher(BlockCipher paramBlockCipher) {
    this(paramBlockCipher, paramBlockCipher.getBlockSize() * 8);
  }
  
  public G3413CFBBlockCipher(BlockCipher paramBlockCipher, int paramInt) {
    super(paramBlockCipher);
    if (paramInt < 0 || paramInt > paramBlockCipher.getBlockSize() * 8)
      throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= " + (paramBlockCipher.getBlockSize() * 8)); 
    this.blockSize = paramBlockCipher.getBlockSize();
    this.cipher = paramBlockCipher;
    this.s = paramInt / 8;
    this.inBuf = new byte[getBlockSize()];
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
    return this.cipher.getAlgorithmName() + "/CFB" + (this.blockSize * 8);
  }
  
  public int getBlockSize() {
    return this.s;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) throws DataLengthException, IllegalStateException {
    processBytes(paramArrayOfbyte1, paramInt1, getBlockSize(), paramArrayOfbyte2, paramInt2);
    return getBlockSize();
  }
  
  protected byte calculateByte(byte paramByte) {
    if (this.byteCount == 0)
      this.gamma = createGamma(); 
    byte b = (byte)(this.gamma[this.byteCount] ^ paramByte);
    this.inBuf[this.byteCount++] = this.forEncryption ? b : paramByte;
    if (this.byteCount == getBlockSize()) {
      this.byteCount = 0;
      generateR(this.inBuf);
    } 
    return b;
  }
  
  byte[] createGamma() {
    byte[] arrayOfByte1 = GOST3413CipherUtil.MSB(this.R, this.blockSize);
    byte[] arrayOfByte2 = new byte[arrayOfByte1.length];
    this.cipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
    return GOST3413CipherUtil.MSB(arrayOfByte2, this.s);
  }
  
  void generateR(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = GOST3413CipherUtil.LSB(this.R, this.m - this.s);
    System.arraycopy(arrayOfByte, 0, this.R, 0, arrayOfByte.length);
    System.arraycopy(paramArrayOfbyte, 0, this.R, arrayOfByte.length, this.m - arrayOfByte.length);
  }
  
  public void reset() {
    this.byteCount = 0;
    Arrays.clear(this.inBuf);
    Arrays.clear(this.gamma);
    if (this.initialized) {
      System.arraycopy(this.R_init, 0, this.R, 0, this.R_init.length);
      this.cipher.reset();
    } 
  }
}
