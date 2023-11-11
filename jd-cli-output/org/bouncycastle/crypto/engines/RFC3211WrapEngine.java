package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Wrapper;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;

public class RFC3211WrapEngine implements Wrapper {
  private CBCBlockCipher engine;
  
  private ParametersWithIV param;
  
  private boolean forWrapping;
  
  private SecureRandom rand;
  
  public RFC3211WrapEngine(BlockCipher paramBlockCipher) {
    this.engine = new CBCBlockCipher(paramBlockCipher);
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    this.forWrapping = paramBoolean;
    if (paramCipherParameters instanceof ParametersWithRandom) {
      ParametersWithRandom parametersWithRandom = (ParametersWithRandom)paramCipherParameters;
      this.rand = parametersWithRandom.getRandom();
      if (!(parametersWithRandom.getParameters() instanceof ParametersWithIV))
        throw new IllegalArgumentException("RFC3211Wrap requires an IV"); 
      this.param = (ParametersWithIV)parametersWithRandom.getParameters();
    } else {
      if (paramBoolean)
        this.rand = CryptoServicesRegistrar.getSecureRandom(); 
      if (!(paramCipherParameters instanceof ParametersWithIV))
        throw new IllegalArgumentException("RFC3211Wrap requires an IV"); 
      this.param = (ParametersWithIV)paramCipherParameters;
    } 
  }
  
  public String getAlgorithmName() {
    return this.engine.getUnderlyingCipher().getAlgorithmName() + "/RFC3211Wrap";
  }
  
  public byte[] wrap(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    byte[] arrayOfByte1;
    if (!this.forWrapping)
      throw new IllegalStateException("not set for wrapping"); 
    if (paramInt2 > 255 || paramInt2 < 0)
      throw new IllegalArgumentException("input must be from 0 to 255 bytes"); 
    this.engine.init(true, this.param);
    int i = this.engine.getBlockSize();
    if (paramInt2 + 4 < i * 2) {
      arrayOfByte1 = new byte[i * 2];
    } else {
      arrayOfByte1 = new byte[((paramInt2 + 4) % i == 0) ? (paramInt2 + 4) : (((paramInt2 + 4) / i + 1) * i)];
    } 
    arrayOfByte1[0] = (byte)paramInt2;
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte1, 4, paramInt2);
    byte[] arrayOfByte2 = new byte[arrayOfByte1.length - paramInt2 + 4];
    this.rand.nextBytes(arrayOfByte2);
    System.arraycopy(arrayOfByte2, 0, arrayOfByte1, paramInt2 + 4, arrayOfByte2.length);
    arrayOfByte1[1] = (byte)(arrayOfByte1[4] ^ 0xFFFFFFFF);
    arrayOfByte1[2] = (byte)(arrayOfByte1[5] ^ 0xFFFFFFFF);
    arrayOfByte1[3] = (byte)(arrayOfByte1[6] ^ 0xFFFFFFFF);
    int j;
    for (j = 0; j < arrayOfByte1.length; j += i)
      this.engine.processBlock(arrayOfByte1, j, arrayOfByte1, j); 
    for (j = 0; j < arrayOfByte1.length; j += i)
      this.engine.processBlock(arrayOfByte1, j, arrayOfByte1, j); 
    return arrayOfByte1;
  }
  
  public byte[] unwrap(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws InvalidCipherTextException {
    byte[] arrayOfByte3;
    if (this.forWrapping)
      throw new IllegalStateException("not set for unwrapping"); 
    int i = this.engine.getBlockSize();
    if (paramInt2 < 2 * i)
      throw new InvalidCipherTextException("input too short"); 
    byte[] arrayOfByte1 = new byte[paramInt2];
    byte[] arrayOfByte2 = new byte[i];
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte1, 0, paramInt2);
    System.arraycopy(paramArrayOfbyte, paramInt1, arrayOfByte2, 0, arrayOfByte2.length);
    this.engine.init(false, new ParametersWithIV(this.param.getParameters(), arrayOfByte2));
    int j;
    for (j = i; j < arrayOfByte1.length; j += i)
      this.engine.processBlock(arrayOfByte1, j, arrayOfByte1, j); 
    System.arraycopy(arrayOfByte1, arrayOfByte1.length - arrayOfByte2.length, arrayOfByte2, 0, arrayOfByte2.length);
    this.engine.init(false, new ParametersWithIV(this.param.getParameters(), arrayOfByte2));
    this.engine.processBlock(arrayOfByte1, 0, arrayOfByte1, 0);
    this.engine.init(false, this.param);
    for (j = 0; j < arrayOfByte1.length; j += i)
      this.engine.processBlock(arrayOfByte1, j, arrayOfByte1, j); 
    j = ((arrayOfByte1[0] & 0xFF) > arrayOfByte1.length - 4) ? 1 : 0;
    if (j != 0) {
      arrayOfByte3 = new byte[arrayOfByte1.length - 4];
    } else {
      arrayOfByte3 = new byte[arrayOfByte1[0] & 0xFF];
    } 
    System.arraycopy(arrayOfByte1, 4, arrayOfByte3, 0, arrayOfByte3.length);
    int k = 0;
    for (byte b = 0; b != 3; b++) {
      byte b1 = (byte)(arrayOfByte1[1 + b] ^ 0xFFFFFFFF);
      k |= b1 ^ arrayOfByte1[4 + b];
    } 
    Arrays.clear(arrayOfByte1);
    if ((((k != 0) ? 1 : 0) | j) != 0)
      throw new InvalidCipherTextException("wrapped key corrupted"); 
    return arrayOfByte3;
  }
}
