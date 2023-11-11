package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class G3413CTRBlockCipher extends StreamBlockCipher {
  private final int s;
  
  private byte[] CTR;
  
  private byte[] IV;
  
  private byte[] buf;
  
  private final int blockSize;
  
  private final BlockCipher cipher;
  
  private int byteCount = 0;
  
  private boolean initialized;
  
  public G3413CTRBlockCipher(BlockCipher paramBlockCipher) {
    this(paramBlockCipher, paramBlockCipher.getBlockSize() * 8);
  }
  
  public G3413CTRBlockCipher(BlockCipher paramBlockCipher, int paramInt) {
    super(paramBlockCipher);
    if (paramInt < 0 || paramInt > paramBlockCipher.getBlockSize() * 8)
      throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= " + (paramBlockCipher.getBlockSize() * 8)); 
    this.cipher = paramBlockCipher;
    this.blockSize = paramBlockCipher.getBlockSize();
    this.s = paramInt / 8;
    this.CTR = new byte[this.blockSize];
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) throws IllegalArgumentException {
    if (paramCipherParameters instanceof ParametersWithIV) {
      ParametersWithIV parametersWithIV = (ParametersWithIV)paramCipherParameters;
      initArrays();
      this.IV = Arrays.clone(parametersWithIV.getIV());
      if (this.IV.length != this.blockSize / 2)
        throw new IllegalArgumentException("Parameter IV length must be == blockSize/2"); 
      System.arraycopy(this.IV, 0, this.CTR, 0, this.IV.length);
      for (int i = this.IV.length; i < this.blockSize; i++)
        this.CTR[i] = 0; 
      if (parametersWithIV.getParameters() != null)
        this.cipher.init(true, parametersWithIV.getParameters()); 
    } else {
      initArrays();
      if (paramCipherParameters != null)
        this.cipher.init(true, paramCipherParameters); 
    } 
    this.initialized = true;
  }
  
  private void initArrays() {
    this.IV = new byte[this.blockSize / 2];
    this.CTR = new byte[this.blockSize];
    this.buf = new byte[this.s];
  }
  
  public String getAlgorithmName() {
    return this.cipher.getAlgorithmName() + "/GCTR";
  }
  
  public int getBlockSize() {
    return this.s;
  }
  
  public int processBlock(byte[] paramArrayOfbyte1, int paramInt1, byte[] paramArrayOfbyte2, int paramInt2) throws DataLengthException, IllegalStateException {
    processBytes(paramArrayOfbyte1, paramInt1, this.s, paramArrayOfbyte2, paramInt2);
    return this.s;
  }
  
  protected byte calculateByte(byte paramByte) {
    if (this.byteCount == 0)
      this.buf = generateBuf(); 
    byte b = (byte)(this.buf[this.byteCount] ^ paramByte);
    this.byteCount++;
    if (this.byteCount == this.s) {
      this.byteCount = 0;
      generateCRT();
    } 
    return b;
  }
  
  private void generateCRT() {
    this.CTR[this.CTR.length - 1] = (byte)(this.CTR[this.CTR.length - 1] + 1);
  }
  
  private byte[] generateBuf() {
    byte[] arrayOfByte = new byte[this.CTR.length];
    this.cipher.processBlock(this.CTR, 0, arrayOfByte, 0);
    return GOST3413CipherUtil.MSB(arrayOfByte, this.s);
  }
  
  public void reset() {
    if (this.initialized) {
      System.arraycopy(this.IV, 0, this.CTR, 0, this.IV.length);
      for (int i = this.IV.length; i < this.blockSize; i++)
        this.CTR[i] = 0; 
      this.byteCount = 0;
      this.cipher.reset();
    } 
  }
}
