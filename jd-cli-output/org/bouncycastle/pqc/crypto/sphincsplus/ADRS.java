package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

class ADRS {
  public static final int WOTS_HASH = 0;
  
  public static final int WOTS_PK = 1;
  
  public static final int TREE = 2;
  
  public static final int FORS_TREE = 3;
  
  public static final int FORS_ROOTS = 4;
  
  static final int OFFSET_LAYER = 0;
  
  static final int OFFSET_TREE = 4;
  
  static final int OFFSET_TREE_HGT = 24;
  
  static final int OFFSET_TREE_INDEX = 28;
  
  static final int OFFSET_TYPE = 16;
  
  static final int OFFSET_KP_ADDR = 20;
  
  static final int OFFSET_CHAIN_ADDR = 24;
  
  static final int OFFSET_HASH_ADDR = 28;
  
  final byte[] value = new byte[32];
  
  ADRS() {}
  
  ADRS(ADRS paramADRS) {
    System.arraycopy(paramADRS.value, 0, this.value, 0, paramADRS.value.length);
  }
  
  public void setLayerAddress(int paramInt) {
    Pack.intToBigEndian(paramInt, this.value, 0);
  }
  
  public int getLayerAddress() {
    return Pack.bigEndianToInt(this.value, 0);
  }
  
  public void setTreeAddress(long paramLong) {
    Pack.longToBigEndian(paramLong, this.value, 8);
  }
  
  public long getTreeAddress() {
    return Pack.bigEndianToLong(this.value, 8);
  }
  
  public void setTreeHeight(int paramInt) {
    Pack.intToBigEndian(paramInt, this.value, 24);
  }
  
  public int getTreeHeight() {
    return Pack.bigEndianToInt(this.value, 24);
  }
  
  public void setTreeIndex(int paramInt) {
    Pack.intToBigEndian(paramInt, this.value, 28);
  }
  
  public int getTreeIndex() {
    return Pack.bigEndianToInt(this.value, 28);
  }
  
  public void setType(int paramInt) {
    Pack.intToBigEndian(paramInt, this.value, 16);
    Arrays.fill(this.value, 20, this.value.length, (byte)0);
  }
  
  public int getType() {
    return Pack.bigEndianToInt(this.value, 16);
  }
  
  public void setKeyPairAddress(int paramInt) {
    Pack.intToBigEndian(paramInt, this.value, 20);
  }
  
  public int getKeyPairAddress() {
    return Pack.bigEndianToInt(this.value, 20);
  }
  
  public void setHashAddress(int paramInt) {
    Pack.intToBigEndian(paramInt, this.value, 28);
  }
  
  public void setChainAddress(int paramInt) {
    Pack.intToBigEndian(paramInt, this.value, 24);
  }
}
