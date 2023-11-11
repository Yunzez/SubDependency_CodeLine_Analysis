package org.bouncycastle.pqc.crypto.gmss.util;

import org.bouncycastle.crypto.Digest;

public class WinternitzOTSVerify {
  private Digest messDigestOTS;
  
  private int mdsize;
  
  private int w;
  
  public WinternitzOTSVerify(Digest paramDigest, int paramInt) {
    this.w = paramInt;
    this.messDigestOTS = paramDigest;
    this.mdsize = this.messDigestOTS.getDigestSize();
  }
  
  public int getSignatureLength() {
    int i = this.messDigestOTS.getDigestSize();
    int j = ((i << 3) + this.w - 1) / this.w;
    int k = getLog((j << this.w) + 1);
    j += (k + this.w - 1) / this.w;
    return i * j;
  }
  
  public byte[] Verify(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte1 = new byte[this.mdsize];
    this.messDigestOTS.update(paramArrayOfbyte1, 0, paramArrayOfbyte1.length);
    this.messDigestOTS.doFinal(arrayOfByte1, 0);
    int i = ((this.mdsize << 3) + this.w - 1) / this.w;
    int j = getLog((i << this.w) + 1);
    int k = i + (j + this.w - 1) / this.w;
    int m = this.mdsize * k;
    if (m != paramArrayOfbyte2.length)
      return null; 
    byte[] arrayOfByte2 = new byte[m];
    int n = 0;
    byte b = 0;
    if (8 % this.w == 0) {
      int i1 = 8 / this.w;
      int i2 = (1 << this.w) - 1;
      int i3;
      for (i3 = 0; i3 < arrayOfByte1.length; i3++) {
        for (byte b1 = 0; b1 < i1; b1++) {
          int i4 = arrayOfByte1[i3] & i2;
          n += i4;
          hashSignatureBlock(paramArrayOfbyte2, b * this.mdsize, i2 - i4, arrayOfByte2, b * this.mdsize);
          arrayOfByte1[i3] = (byte)(arrayOfByte1[i3] >>> this.w);
          b++;
        } 
      } 
      n = (i << this.w) - n;
      for (i3 = 0; i3 < j; i3 += this.w) {
        int i4 = n & i2;
        hashSignatureBlock(paramArrayOfbyte2, b * this.mdsize, i2 - i4, arrayOfByte2, b * this.mdsize);
        n >>>= this.w;
        b++;
      } 
    } else if (this.w < 8) {
      int i1 = this.mdsize / this.w;
      int i2 = (1 << this.w) - 1;
      byte b1 = 0;
      int i3;
      for (i3 = 0; i3 < i1; i3++) {
        long l1 = 0L;
        byte b2;
        for (b2 = 0; b2 < this.w; b2++) {
          l1 ^= ((arrayOfByte1[b1] & 0xFF) << b2 << 3);
          b1++;
        } 
        for (b2 = 0; b2 < 8; b2++) {
          int i4 = (int)(l1 & i2);
          n += i4;
          hashSignatureBlock(paramArrayOfbyte2, b * this.mdsize, i2 - i4, arrayOfByte2, b * this.mdsize);
          l1 >>>= this.w;
          b++;
        } 
      } 
      i1 = this.mdsize % this.w;
      long l = 0L;
      for (i3 = 0; i3 < i1; i3++) {
        l ^= ((arrayOfByte1[b1] & 0xFF) << i3 << 3);
        b1++;
      } 
      i1 <<= 3;
      for (i3 = 0; i3 < i1; i3 += this.w) {
        int i4 = (int)(l & i2);
        n += i4;
        hashSignatureBlock(paramArrayOfbyte2, b * this.mdsize, i2 - i4, arrayOfByte2, b * this.mdsize);
        l >>>= this.w;
        b++;
      } 
      n = (i << this.w) - n;
      for (i3 = 0; i3 < j; i3 += this.w) {
        int i4 = n & i2;
        hashSignatureBlock(paramArrayOfbyte2, b * this.mdsize, i2 - i4, arrayOfByte2, b * this.mdsize);
        n >>>= this.w;
        b++;
      } 
    } else if (this.w < 57) {
      int i1 = (this.mdsize << 3) - this.w;
      int i2 = (1 << this.w) - 1;
      byte[] arrayOfByte = new byte[this.mdsize];
      int i3 = 0;
      while (i3 <= i1) {
        int i6 = i3 >>> 3;
        int i8 = i3 % 8;
        i3 += this.w;
        int i7 = i3 + 7 >>> 3;
        long l1 = 0L;
        byte b1 = 0;
        for (int i9 = i6; i9 < i7; i9++) {
          l1 ^= ((arrayOfByte1[i9] & 0xFF) << b1 << 3);
          b1++;
        } 
        l1 >>>= i8;
        long l2 = l1 & i2;
        n = (int)(n + l2);
        System.arraycopy(paramArrayOfbyte2, b * this.mdsize, arrayOfByte, 0, this.mdsize);
        while (l2 < i2) {
          this.messDigestOTS.update(arrayOfByte, 0, arrayOfByte.length);
          this.messDigestOTS.doFinal(arrayOfByte, 0);
          l2++;
        } 
        System.arraycopy(arrayOfByte, 0, arrayOfByte2, b * this.mdsize, this.mdsize);
        b++;
      } 
      int i4 = i3 >>> 3;
      if (i4 < this.mdsize) {
        int i6 = i3 % 8;
        long l1 = 0L;
        byte b1 = 0;
        for (int i7 = i4; i7 < this.mdsize; i7++) {
          l1 ^= ((arrayOfByte1[i7] & 0xFF) << b1 << 3);
          b1++;
        } 
        l1 >>>= i6;
        long l2 = l1 & i2;
        n = (int)(n + l2);
        System.arraycopy(paramArrayOfbyte2, b * this.mdsize, arrayOfByte, 0, this.mdsize);
        while (l2 < i2) {
          this.messDigestOTS.update(arrayOfByte, 0, arrayOfByte.length);
          this.messDigestOTS.doFinal(arrayOfByte, 0);
          l2++;
        } 
        System.arraycopy(arrayOfByte, 0, arrayOfByte2, b * this.mdsize, this.mdsize);
        b++;
      } 
      n = (i << this.w) - n;
      int i5;
      for (i5 = 0; i5 < j; i5 += this.w) {
        long l = (n & i2);
        System.arraycopy(paramArrayOfbyte2, b * this.mdsize, arrayOfByte, 0, this.mdsize);
        while (l < i2) {
          this.messDigestOTS.update(arrayOfByte, 0, arrayOfByte.length);
          this.messDigestOTS.doFinal(arrayOfByte, 0);
          l++;
        } 
        System.arraycopy(arrayOfByte, 0, arrayOfByte2, b * this.mdsize, this.mdsize);
        n >>>= this.w;
        b++;
      } 
    } 
    this.messDigestOTS.update(arrayOfByte2, 0, arrayOfByte2.length);
    byte[] arrayOfByte3 = new byte[this.mdsize];
    this.messDigestOTS.doFinal(arrayOfByte3, 0);
    return arrayOfByte3;
  }
  
  public int getLog(int paramInt) {
    byte b = 1;
    int i = 2;
    while (i < paramInt) {
      i <<= 1;
      b++;
    } 
    return b;
  }
  
  private void hashSignatureBlock(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    if (paramInt2 < 1) {
      System.arraycopy(paramArrayOfbyte1, paramInt1, paramArrayOfbyte2, paramInt3, this.mdsize);
    } else {
      this.messDigestOTS.update(paramArrayOfbyte1, paramInt1, this.mdsize);
      this.messDigestOTS.doFinal(paramArrayOfbyte2, paramInt3);
      while (--paramInt2 > 0) {
        this.messDigestOTS.update(paramArrayOfbyte2, paramInt3, this.mdsize);
        this.messDigestOTS.doFinal(paramArrayOfbyte2, paramInt3);
      } 
    } 
  }
}
