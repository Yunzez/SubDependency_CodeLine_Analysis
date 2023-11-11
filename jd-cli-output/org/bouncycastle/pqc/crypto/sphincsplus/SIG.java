package org.bouncycastle.pqc.crypto.sphincsplus;

class SIG {
  private final byte[] r;
  
  private final SIG_FORS[] sig_fors;
  
  private final SIG_XMSS[] sig_ht;
  
  public SIG(int paramInt1, int paramInt2, int paramInt3, int paramInt4, int paramInt5, int paramInt6, byte[] paramArrayOfbyte) {
    this.r = new byte[paramInt1];
    System.arraycopy(paramArrayOfbyte, 0, this.r, 0, paramInt1);
    this.sig_fors = new SIG_FORS[paramInt2];
    int i = paramInt1;
    int j;
    for (j = 0; j != paramInt2; j++) {
      byte[] arrayOfByte = new byte[paramInt1];
      System.arraycopy(paramArrayOfbyte, i, arrayOfByte, 0, paramInt1);
      i += paramInt1;
      byte[][] arrayOfByte1 = new byte[paramInt3][];
      for (int k = 0; k != paramInt3; k++) {
        arrayOfByte1[k] = new byte[paramInt1];
        System.arraycopy(paramArrayOfbyte, i, arrayOfByte1[k], 0, paramInt1);
        i += paramInt1;
      } 
      this.sig_fors[j] = new SIG_FORS(arrayOfByte, arrayOfByte1);
    } 
    this.sig_ht = new SIG_XMSS[paramInt4];
    for (j = 0; j != paramInt4; j++) {
      byte[] arrayOfByte = new byte[paramInt6 * paramInt1];
      System.arraycopy(paramArrayOfbyte, i, arrayOfByte, 0, arrayOfByte.length);
      i += arrayOfByte.length;
      byte[][] arrayOfByte1 = new byte[paramInt5][];
      for (int k = 0; k != paramInt5; k++) {
        arrayOfByte1[k] = new byte[paramInt1];
        System.arraycopy(paramArrayOfbyte, i, arrayOfByte1[k], 0, paramInt1);
        i += paramInt1;
      } 
      this.sig_ht[j] = new SIG_XMSS(arrayOfByte, arrayOfByte1);
    } 
    if (i != paramArrayOfbyte.length)
      throw new IllegalArgumentException("signature wrong length"); 
  }
  
  public byte[] getR() {
    return this.r;
  }
  
  public SIG_FORS[] getSIG_FORS() {
    return this.sig_fors;
  }
  
  public SIG_XMSS[] getSIG_HT() {
    return this.sig_ht;
  }
}
