package org.bouncycastle.crypto.fpe;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

public class FPEFF3_1Engine extends FPEEngine {
  public FPEFF3_1Engine() {
    this(new AESEngine());
  }
  
  public FPEFF3_1Engine(BlockCipher paramBlockCipher) {
    super(paramBlockCipher);
    if (paramBlockCipher.getBlockSize() != 16)
      throw new IllegalArgumentException("base cipher needs to be 128 bits"); 
    if (Properties.isOverrideSet("org.bouncycastle.fpe.disable"))
      throw new UnsupportedOperationException("FPE disabled"); 
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    this.forEncryption = paramBoolean;
    this.fpeParameters = (FPEParameters)paramCipherParameters;
    this.baseCipher.init(!this.fpeParameters.isUsingInverseFunction(), new KeyParameter(Arrays.reverse(this.fpeParameters.getKey().getKey())));
    if ((this.fpeParameters.getTweak()).length != 7)
      throw new IllegalArgumentException("tweak should be 56 bits"); 
  }
  
  public String getAlgorithmName() {
    return "FF3-1";
  }
  
  protected int encryptBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    byte[] arrayOfByte;
    if (this.fpeParameters.getRadix() > 256) {
      arrayOfByte = toByteArray(SP80038G.encryptFF3_1w(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), toShortArray(paramArrayOfbyte1), paramInt1, paramInt2 / 2));
    } else {
      arrayOfByte = SP80038G.encryptFF3_1(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), paramArrayOfbyte1, paramInt1, paramInt2);
    } 
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, paramInt3, paramInt2);
    return paramInt2;
  }
  
  protected int decryptBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    byte[] arrayOfByte;
    if (this.fpeParameters.getRadix() > 256) {
      arrayOfByte = toByteArray(SP80038G.decryptFF3_1w(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), toShortArray(paramArrayOfbyte1), paramInt1, paramInt2 / 2));
    } else {
      arrayOfByte = SP80038G.decryptFF3_1(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), paramArrayOfbyte1, paramInt1, paramInt2);
    } 
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, paramInt3, paramInt2);
    return paramInt2;
  }
}
