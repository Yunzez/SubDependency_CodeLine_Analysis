package org.bouncycastle.pqc.crypto.sphincsplus;

class NodeEntry {
  final byte[] nodeValue;
  
  final int nodeHeight;
  
  NodeEntry(byte[] paramArrayOfbyte, int paramInt) {
    this.nodeValue = paramArrayOfbyte;
    this.nodeHeight = paramInt;
  }
}
