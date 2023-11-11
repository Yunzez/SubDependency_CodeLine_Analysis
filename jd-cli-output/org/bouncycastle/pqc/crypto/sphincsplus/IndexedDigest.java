package org.bouncycastle.pqc.crypto.sphincsplus;

class IndexedDigest {
  final long idx_tree;
  
  final int idx_leaf;
  
  final byte[] digest;
  
  IndexedDigest(long paramLong, int paramInt, byte[] paramArrayOfbyte) {
    this.idx_tree = paramLong;
    this.idx_leaf = paramInt;
    this.digest = paramArrayOfbyte;
  }
}
