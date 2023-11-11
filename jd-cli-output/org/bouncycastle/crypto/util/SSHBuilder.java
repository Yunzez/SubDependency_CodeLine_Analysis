package org.bouncycastle.crypto.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.util.Strings;

class SSHBuilder {
  private final ByteArrayOutputStream bos = new ByteArrayOutputStream();
  
  public void u32(int paramInt) {
    this.bos.write(paramInt >>> 24 & 0xFF);
    this.bos.write(paramInt >>> 16 & 0xFF);
    this.bos.write(paramInt >>> 8 & 0xFF);
    this.bos.write(paramInt & 0xFF);
  }
  
  public void writeBigNum(BigInteger paramBigInteger) {
    writeBlock(paramBigInteger.toByteArray());
  }
  
  public void writeBlock(byte[] paramArrayOfbyte) {
    u32(paramArrayOfbyte.length);
    try {
      this.bos.write(paramArrayOfbyte);
    } catch (IOException iOException) {
      throw new IllegalStateException(iOException.getMessage(), iOException);
    } 
  }
  
  public void writeBytes(byte[] paramArrayOfbyte) {
    try {
      this.bos.write(paramArrayOfbyte);
    } catch (IOException iOException) {
      throw new IllegalStateException(iOException.getMessage(), iOException);
    } 
  }
  
  public void writeString(String paramString) {
    writeBlock(Strings.toByteArray(paramString));
  }
  
  public byte[] getBytes() {
    return this.bos.toByteArray();
  }
  
  public byte[] getPaddedBytes() {
    return getPaddedBytes(8);
  }
  
  public byte[] getPaddedBytes(int paramInt) {
    int i = this.bos.size() % paramInt;
    if (0 != i) {
      int j = paramInt - i;
      for (byte b = 1; b <= j; b++)
        this.bos.write(b); 
    } 
    return this.bos.toByteArray();
  }
}
