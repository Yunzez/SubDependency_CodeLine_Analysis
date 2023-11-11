package org.bouncycastle.crypto.util;

import java.math.BigInteger;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

class SSHBuffer {
  private final byte[] buffer;
  
  private int pos = 0;
  
  public SSHBuffer(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    this.buffer = paramArrayOfbyte2;
    for (byte b = 0; b != paramArrayOfbyte1.length; b++) {
      if (paramArrayOfbyte1[b] != paramArrayOfbyte2[b])
        throw new IllegalArgumentException("magic-number incorrect"); 
    } 
    this.pos += paramArrayOfbyte1.length;
  }
  
  public SSHBuffer(byte[] paramArrayOfbyte) {
    this.buffer = paramArrayOfbyte;
  }
  
  public int readU32() {
    if (this.pos > this.buffer.length - 4)
      throw new IllegalArgumentException("4 bytes for U32 exceeds buffer."); 
    int i = (this.buffer[this.pos++] & 0xFF) << 24;
    i |= (this.buffer[this.pos++] & 0xFF) << 16;
    i |= (this.buffer[this.pos++] & 0xFF) << 8;
    i |= this.buffer[this.pos++] & 0xFF;
    return i;
  }
  
  public String readString() {
    return Strings.fromByteArray(readBlock());
  }
  
  public byte[] readBlock() {
    int i = readU32();
    if (i == 0)
      return new byte[0]; 
    if (this.pos > this.buffer.length - i)
      throw new IllegalArgumentException("not enough data for block"); 
    int j = this.pos;
    this.pos += i;
    return Arrays.copyOfRange(this.buffer, j, this.pos);
  }
  
  public void skipBlock() {
    int i = readU32();
    if (this.pos > this.buffer.length - i)
      throw new IllegalArgumentException("not enough data for block"); 
    this.pos += i;
  }
  
  public byte[] readPaddedBlock() {
    return readPaddedBlock(8);
  }
  
  public byte[] readPaddedBlock(int paramInt) {
    int i = readU32();
    if (i == 0)
      return new byte[0]; 
    if (this.pos > this.buffer.length - i)
      throw new IllegalArgumentException("not enough data for block"); 
    int j = i % paramInt;
    if (0 != j)
      throw new IllegalArgumentException("missing padding"); 
    int k = this.pos;
    this.pos += i;
    int m = this.pos;
    if (i > 0) {
      int n = this.buffer[this.pos - 1] & 0xFF;
      if (0 < n && n < paramInt) {
        int i1 = n;
        m -= i1;
        byte b = 1;
        for (int i2 = m; b <= i1; i2++) {
          if (b != (this.buffer[i2] & 0xFF))
            throw new IllegalArgumentException("incorrect padding"); 
          b++;
        } 
      } 
    } 
    return Arrays.copyOfRange(this.buffer, k, m);
  }
  
  public BigInteger readBigNumPositive() {
    int i = readU32();
    if (this.pos + i > this.buffer.length)
      throw new IllegalArgumentException("not enough data for big num"); 
    int j = this.pos;
    this.pos += i;
    byte[] arrayOfByte = Arrays.copyOfRange(this.buffer, j, this.pos);
    return new BigInteger(1, arrayOfByte);
  }
  
  public byte[] getBuffer() {
    return Arrays.clone(this.buffer);
  }
  
  public boolean hasRemaining() {
    return (this.pos < this.buffer.length);
  }
}
