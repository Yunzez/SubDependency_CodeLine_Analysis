package org.bouncycastle.crypto.fpe;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.util.Properties;

public class FPEFF1Engine extends FPEEngine {
  public FPEFF1Engine() {
    this(new AESEngine());
  }
  
  public FPEFF1Engine(BlockCipher paramBlockCipher) {
    super(paramBlockCipher);
    if (paramBlockCipher.getBlockSize() != 16)
      throw new IllegalArgumentException("base cipher needs to be 128 bits"); 
    if (Properties.isOverrideSet("org.bouncycastle.fpe.disable") || Properties.isOverrideSet("org.bouncycastle.fpe.disable_ff1"))
      throw new UnsupportedOperationException("FF1 encryption disabled"); 
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) {
    this.forEncryption = paramBoolean;
    this.fpeParameters = (FPEParameters)paramCipherParameters;
    this.baseCipher.init(!this.fpeParameters.isUsingInverseFunction(), this.fpeParameters.getKey());
  }
  
  public String getAlgorithmName() {
    return "FF1";
  }
  
  protected int encryptBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    byte[] arrayOfByte;
    if (this.fpeParameters.getRadix() > 256) {
      arrayOfByte = toByteArray(SP80038G.encryptFF1w(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), toShortArray(paramArrayOfbyte1), paramInt1, paramInt2 / 2));
    } else {
      arrayOfByte = SP80038G.encryptFF1(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), paramArrayOfbyte1, paramInt1, paramInt2);
    } 
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, paramInt3, paramInt2);
    return paramInt2;
  }
  
  protected int decryptBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    byte[] arrayOfByte;
    if (this.fpeParameters.getRadix() > 256) {
      arrayOfByte = toByteArray(SP80038G.decryptFF1w(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), toShortArray(paramArrayOfbyte1), paramInt1, paramInt2 / 2));
    } else {
      arrayOfByte = SP80038G.decryptFF1(this.baseCipher, this.fpeParameters.getRadix(), this.fpeParameters.getTweak(), paramArrayOfbyte1, paramInt1, paramInt2);
    } 
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte2, paramInt3, paramInt2);
    return paramInt2;
  }
}
