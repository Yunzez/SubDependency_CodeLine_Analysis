package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier;
import org.bouncycastle.crypto.modes.kgcm.Tables16kKGCMMultiplier_512;
import org.bouncycastle.crypto.modes.kgcm.Tables4kKGCMMultiplier_128;
import org.bouncycastle.crypto.modes.kgcm.Tables8kKGCMMultiplier_256;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class KGCMBlockCipher implements AEADBlockCipher {
  private static final int MIN_MAC_BITS = 64;
  
  private BlockCipher engine;
  
  private BufferedBlockCipher ctrEngine;
  
  private int macSize;
  
  private boolean forEncryption;
  
  private byte[] initialAssociatedText;
  
  private byte[] macBlock;
  
  private byte[] iv;
  
  private KGCMMultiplier multiplier;
  
  private long[] b;
  
  private final int blockSize;
  
  private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
  
  private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();
  
  private static KGCMMultiplier createDefaultMultiplier(int paramInt) {
    switch (paramInt) {
      case 16:
        return new Tables4kKGCMMultiplier_128();
      case 32:
        return new Tables8kKGCMMultiplier_256();
      case 64:
        return new Tables16kKGCMMultiplier_512();
    } 
    throw new IllegalArgumentException("Only 128, 256, and 512 -bit block sizes supported");
  }
  
  public KGCMBlockCipher(BlockCipher paramBlockCipher) {
    this.engine = paramBlockCipher;
    this.ctrEngine = new BufferedBlockCipher(new KCTRBlockCipher(this.engine));
    this.macSize = -1;
    this.blockSize = this.engine.getBlockSize();
    this.initialAssociatedText = new byte[this.blockSize];
    this.iv = new byte[this.blockSize];
    this.multiplier = createDefaultMultiplier(this.blockSize);
    this.b = new long[this.blockSize >>> 3];
    this.macBlock = null;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) throws IllegalArgumentException {
    KeyParameter keyParameter;
    this.forEncryption = paramBoolean;
    if (paramCipherParameters instanceof AEADParameters) {
      AEADParameters aEADParameters = (AEADParameters)paramCipherParameters;
      byte[] arrayOfByte = aEADParameters.getNonce();
      int i = this.iv.length - arrayOfByte.length;
      Arrays.fill(this.iv, (byte)0);
      System.arraycopy(arrayOfByte, 0, this.iv, i, arrayOfByte.length);
      this.initialAssociatedText = aEADParameters.getAssociatedText();
      int j = aEADParameters.getMacSize();
      if (j < 64 || j > this.blockSize << 3 || (j & 0x7) != 0)
        throw new IllegalArgumentException("Invalid value for MAC size: " + j); 
      this.macSize = j >>> 3;
      keyParameter = aEADParameters.getKey();
      if (this.initialAssociatedText != null)
        processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length); 
    } else if (paramCipherParameters instanceof ParametersWithIV) {
      ParametersWithIV parametersWithIV = (ParametersWithIV)paramCipherParameters;
      byte[] arrayOfByte = parametersWithIV.getIV();
      int i = this.iv.length - arrayOfByte.length;
      Arrays.fill(this.iv, (byte)0);
      System.arraycopy(arrayOfByte, 0, this.iv, i, arrayOfByte.length);
      this.initialAssociatedText = null;
      this.macSize = this.blockSize;
      keyParameter = (KeyParameter)parametersWithIV.getParameters();
    } else {
      throw new IllegalArgumentException("Invalid parameter passed");
    } 
    this.macBlock = new byte[this.blockSize];
    this.ctrEngine.init(true, new ParametersWithIV(keyParameter, this.iv));
    this.engine.init(true, keyParameter);
  }
  
  public String getAlgorithmName() {
    return this.engine.getAlgorithmName() + "/KGCM";
  }
  
  public BlockCipher getUnderlyingCipher() {
    return this.engine;
  }
  
  public void processAADByte(byte paramByte) {
    this.associatedText.write(paramByte);
  }
  
  public void processAADBytes(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    this.associatedText.write(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  private void processAAD(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    int i = paramInt1;
    int j = paramInt1 + paramInt2;
    while (i < j) {
      xorWithInput(this.b, paramArrayOfbyte, i);
      this.multiplier.multiplyH(this.b);
      i += this.blockSize;
    } 
  }
  
  public int processByte(byte paramByte, byte[] paramArrayOfbyte, int paramInt) throws DataLengthException, IllegalStateException {
    this.data.write(paramByte);
    return 0;
  }
  
  public int processBytes(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws DataLengthException, IllegalStateException {
    if (paramArrayOfbyte1.length < paramInt1 + paramInt2)
      throw new DataLengthException("input buffer too short"); 
    this.data.write(paramArrayOfbyte1, paramInt1, paramInt2);
    return 0;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) throws IllegalStateException, InvalidCipherTextException {
    int k;
    int i = this.data.size();
    if (!this.forEncryption && i < this.macSize)
      throw new InvalidCipherTextException("data too short"); 
    byte[] arrayOfByte1 = new byte[this.blockSize];
    this.engine.processBlock(arrayOfByte1, 0, arrayOfByte1, 0);
    long[] arrayOfLong = new long[this.blockSize >>> 3];
    Pack.littleEndianToLong(arrayOfByte1, 0, arrayOfLong);
    this.multiplier.init(arrayOfLong);
    Arrays.fill(arrayOfByte1, (byte)0);
    Arrays.fill(arrayOfLong, 0L);
    int j = this.associatedText.size();
    if (j > 0)
      processAAD(this.associatedText.getBuffer(), 0, j); 
    if (this.forEncryption) {
      if (paramArrayOfbyte.length - paramInt - this.macSize < i)
        throw new OutputLengthException("Output buffer too short"); 
      k = this.ctrEngine.processBytes(this.data.getBuffer(), 0, i, paramArrayOfbyte, paramInt);
      k += this.ctrEngine.doFinal(paramArrayOfbyte, paramInt + k);
      calculateMac(paramArrayOfbyte, paramInt, i, j);
    } else {
      int m = i - this.macSize;
      if (paramArrayOfbyte.length - paramInt < m)
        throw new OutputLengthException("Output buffer too short"); 
      calculateMac(this.data.getBuffer(), 0, m, j);
      k = this.ctrEngine.processBytes(this.data.getBuffer(), 0, m, paramArrayOfbyte, paramInt);
      k += this.ctrEngine.doFinal(paramArrayOfbyte, paramInt + k);
    } 
    if (this.macBlock == null)
      throw new IllegalStateException("mac is not calculated"); 
    if (this.forEncryption) {
      System.arraycopy(this.macBlock, 0, paramArrayOfbyte, paramInt + k, this.macSize);
      reset();
      return k + this.macSize;
    } 
    byte[] arrayOfByte2 = new byte[this.macSize];
    System.arraycopy(this.data.getBuffer(), i - this.macSize, arrayOfByte2, 0, this.macSize);
    byte[] arrayOfByte3 = new byte[this.macSize];
    System.arraycopy(this.macBlock, 0, arrayOfByte3, 0, this.macSize);
    if (!Arrays.constantTimeAreEqual(arrayOfByte2, arrayOfByte3))
      throw new InvalidCipherTextException("mac verification failed"); 
    reset();
    return k;
  }
  
  public byte[] getMac() {
    byte[] arrayOfByte = new byte[this.macSize];
    System.arraycopy(this.macBlock, 0, arrayOfByte, 0, this.macSize);
    return arrayOfByte;
  }
  
  public int getUpdateOutputSize(int paramInt) {
    return 0;
  }
  
  public int getOutputSize(int paramInt) {
    int i = paramInt + this.data.size();
    return this.forEncryption ? (i + this.macSize) : ((i < this.macSize) ? 0 : (i - this.macSize));
  }
  
  public void reset() {
    Arrays.fill(this.b, 0L);
    this.engine.reset();
    this.data.reset();
    this.associatedText.reset();
    if (this.initialAssociatedText != null)
      processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length); 
  }
  
  private void calculateMac(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, int paramInt3) {
    int i = paramInt1;
    int j = paramInt1 + paramInt2;
    while (i < j) {
      xorWithInput(this.b, paramArrayOfbyte, i);
      this.multiplier.multiplyH(this.b);
      i += this.blockSize;
    } 
    long l1 = (paramInt3 & 0xFFFFFFFFL) << 3L;
    long l2 = (paramInt2 & 0xFFFFFFFFL) << 3L;
    this.b[0] = this.b[0] ^ l1;
    this.b[this.blockSize >>> 4] = this.b[this.blockSize >>> 4] ^ l2;
    this.macBlock = Pack.longToLittleEndian(this.b);
    this.engine.processBlock(this.macBlock, 0, this.macBlock, 0);
  }
  
  private static void xorWithInput(long[] paramArrayOflong, byte[] paramArrayOfbyte, int paramInt) {
    for (byte b = 0; b < paramArrayOflong.length; b++) {
      paramArrayOflong[b] = paramArrayOflong[b] ^ Pack.littleEndianToLong(paramArrayOfbyte, paramInt);
      paramInt += 8;
    } 
  }
  
  private class ExposedByteArrayOutputStream extends ByteArrayOutputStream {
    public byte[] getBuffer() {
      return this.buf;
    }
  }
}
