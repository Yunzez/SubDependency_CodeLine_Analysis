package org.bouncycastle.crypto.modes;

import org.bouncycastle.util.Arrays;

class GOST3413CipherUtil {
  public static byte[] MSB(byte[] paramArrayOfbyte, int paramInt) {
    return Arrays.copyOf(paramArrayOfbyte, paramInt);
  }
  
  public static byte[] LSB(byte[] paramArrayOfbyte, int paramInt) {
    byte[] arrayOfByte = new byte[paramInt];
    System.arraycopy(paramArrayOfbyte, paramArrayOfbyte.length - paramInt, arrayOfByte, 0, paramInt);
    return arrayOfByte;
  }
  
  public static byte[] sum(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte = new byte[paramArrayOfbyte1.length];
    for (byte b = 0; b < paramArrayOfbyte1.length; b++)
      arrayOfByte[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]); 
    return arrayOfByte;
  }
  
  public static byte[] copyFromInput(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (paramArrayOfbyte.length < paramInt1 + paramInt2)
      paramInt1 = paramArrayOfbyte.length - paramInt2; 
    byte[] arrayOfByte = new byte[paramInt1];
    System.arraycopy(paramArrayOfbyte, paramInt2, arrayOfByte, 0, paramInt1);
    return arrayOfByte;
  }
}
