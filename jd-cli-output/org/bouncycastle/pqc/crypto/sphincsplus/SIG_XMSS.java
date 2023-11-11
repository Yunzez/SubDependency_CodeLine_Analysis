package org.bouncycastle.pqc.crypto.sphincsplus;

class SIG_XMSS {
  final byte[] sig;
  
  final byte[][] auth;
  
  public SIG_XMSS(byte[] paramArrayOfbyte, byte[][] paramArrayOfbyte1) {
    this.sig = paramArrayOfbyte;
    this.auth = paramArrayOfbyte1;
  }
  
  public byte[] getWOTSSig() {
    return this.sig;
  }
  
  public byte[][] getXMSSAUTH() {
    return this.auth;
  }
}
