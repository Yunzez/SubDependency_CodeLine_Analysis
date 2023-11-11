package org.bouncycastle.pqc.crypto.sphincsplus;

class SK {
  final byte[] seed;
  
  final byte[] prf;
  
  SK(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    this.seed = paramArrayOfbyte1;
    this.prf = paramArrayOfbyte2;
  }
}
