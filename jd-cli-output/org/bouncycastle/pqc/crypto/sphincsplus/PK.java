package org.bouncycastle.pqc.crypto.sphincsplus;

class PK {
  final byte[] seed;
  
  final byte[] root;
  
  PK(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    this.seed = paramArrayOfbyte1;
    this.root = paramArrayOfbyte2;
  }
}
