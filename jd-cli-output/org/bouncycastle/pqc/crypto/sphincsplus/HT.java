package org.bouncycastle.pqc.crypto.sphincsplus;

import java.util.LinkedList;
import org.bouncycastle.util.Arrays;

class HT {
  private final byte[] skSeed;
  
  private final byte[] pkSeed;
  
  SPHINCSPlusEngine engine;
  
  WotsPlus wots;
  
  final byte[] htPubKey;
  
  public HT(SPHINCSPlusEngine paramSPHINCSPlusEngine, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    this.skSeed = paramArrayOfbyte1;
    this.pkSeed = paramArrayOfbyte2;
    this.engine = paramSPHINCSPlusEngine;
    this.wots = new WotsPlus(paramSPHINCSPlusEngine);
    ADRS aDRS = new ADRS();
    aDRS.setLayerAddress(paramSPHINCSPlusEngine.D - 1);
    aDRS.setTreeAddress(0L);
    if (paramArrayOfbyte1 != null) {
      this.htPubKey = xmss_PKgen(paramArrayOfbyte1, paramArrayOfbyte2, aDRS);
    } else {
      this.htPubKey = null;
    } 
  }
  
  byte[] sign(byte[] paramArrayOfbyte, long paramLong, int paramInt) {
    ADRS aDRS = new ADRS();
    aDRS.setLayerAddress(0);
    aDRS.setTreeAddress(paramLong);
    SIG_XMSS sIG_XMSS = xmss_sign(paramArrayOfbyte, this.skSeed, paramInt, this.pkSeed, aDRS);
    SIG_XMSS[] arrayOfSIG_XMSS = new SIG_XMSS[this.engine.D];
    arrayOfSIG_XMSS[0] = sIG_XMSS;
    aDRS.setLayerAddress(0);
    aDRS.setTreeAddress(paramLong);
    byte[] arrayOfByte = xmss_pkFromSig(paramInt, sIG_XMSS, paramArrayOfbyte, this.pkSeed, aDRS);
    for (byte b1 = 1; b1 < this.engine.D; b1++) {
      paramInt = (int)(paramLong & ((1 << this.engine.H_PRIME) - 1));
      paramLong >>>= this.engine.H_PRIME;
      aDRS.setLayerAddress(b1);
      aDRS.setTreeAddress(paramLong);
      sIG_XMSS = xmss_sign(arrayOfByte, this.skSeed, paramInt, this.pkSeed, aDRS);
      arrayOfSIG_XMSS[b1] = sIG_XMSS;
      if (b1 < this.engine.D - 1)
        arrayOfByte = xmss_pkFromSig(paramInt, sIG_XMSS, arrayOfByte, this.pkSeed, aDRS); 
    } 
    byte[][] arrayOfByte1 = new byte[arrayOfSIG_XMSS.length][];
    for (byte b2 = 0; b2 != arrayOfByte1.length; b2++)
      arrayOfByte1[b2] = Arrays.concatenate((arrayOfSIG_XMSS[b2]).sig, Arrays.concatenate((arrayOfSIG_XMSS[b2]).auth)); 
    return Arrays.concatenate(arrayOfByte1);
  }
  
  byte[] xmss_PKgen(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, ADRS paramADRS) {
    return treehash(paramArrayOfbyte1, 0, this.engine.H_PRIME, paramArrayOfbyte2, paramADRS);
  }
  
  byte[] xmss_pkFromSig(int paramInt, SIG_XMSS paramSIG_XMSS, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, ADRS paramADRS) {
    ADRS aDRS = new ADRS(paramADRS);
    aDRS.setType(0);
    aDRS.setKeyPairAddress(paramInt);
    byte[] arrayOfByte1 = paramSIG_XMSS.getWOTSSig();
    byte[][] arrayOfByte = paramSIG_XMSS.getXMSSAUTH();
    byte[] arrayOfByte2 = this.wots.pkFromSig(arrayOfByte1, paramArrayOfbyte1, paramArrayOfbyte2, aDRS);
    byte[] arrayOfByte3 = null;
    aDRS.setType(2);
    aDRS.setTreeIndex(paramInt);
    for (byte b = 0; b < this.engine.H_PRIME; b++) {
      aDRS.setTreeHeight(b + 1);
      if (paramInt / (1 << b) % 2 == 0) {
        aDRS.setTreeIndex(aDRS.getTreeIndex() / 2);
        arrayOfByte3 = this.engine.H(paramArrayOfbyte2, aDRS, arrayOfByte2, arrayOfByte[b]);
      } else {
        aDRS.setTreeIndex((aDRS.getTreeIndex() - 1) / 2);
        arrayOfByte3 = this.engine.H(paramArrayOfbyte2, aDRS, arrayOfByte[b], arrayOfByte2);
      } 
      arrayOfByte2 = arrayOfByte3;
    } 
    return arrayOfByte2;
  }
  
  SIG_XMSS xmss_sign(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt, byte[] paramArrayOfbyte3, ADRS paramADRS) {
    byte[][] arrayOfByte = new byte[this.engine.H_PRIME][];
    for (byte b = 0; b < this.engine.H_PRIME; b++) {
      int i = paramInt / (1 << b) ^ 0x1;
      arrayOfByte[b] = treehash(paramArrayOfbyte2, i * (1 << b), b, paramArrayOfbyte3, paramADRS);
    } 
    paramADRS = new ADRS(paramADRS);
    paramADRS.setType(0);
    paramADRS.setKeyPairAddress(paramInt);
    byte[] arrayOfByte1 = this.wots.sign(paramArrayOfbyte1, paramArrayOfbyte2, paramArrayOfbyte3, paramADRS);
    return new SIG_XMSS(arrayOfByte1, arrayOfByte);
  }
  
  byte[] treehash(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, ADRS paramADRS) {
    ADRS aDRS = new ADRS(paramADRS);
    LinkedList<NodeEntry> linkedList = new LinkedList();
    if (paramInt1 % (1 << paramInt2) != 0)
      return null; 
    for (byte b = 0; b < 1 << paramInt2; b++) {
      aDRS.setType(0);
      aDRS.setKeyPairAddress(paramInt1 + b);
      byte[] arrayOfByte = this.wots.pkGen(paramArrayOfbyte1, paramArrayOfbyte2, aDRS);
      aDRS.setType(2);
      aDRS.setTreeHeight(1);
      aDRS.setTreeIndex(paramInt1 + b);
      while (!linkedList.isEmpty() && ((NodeEntry)linkedList.get(0)).nodeHeight == aDRS.getTreeHeight()) {
        aDRS.setTreeIndex((aDRS.getTreeIndex() - 1) / 2);
        NodeEntry nodeEntry = linkedList.remove(0);
        arrayOfByte = this.engine.H(paramArrayOfbyte2, aDRS, nodeEntry.nodeValue, arrayOfByte);
        aDRS.setTreeHeight(aDRS.getTreeHeight() + 1);
      } 
      linkedList.add(0, new NodeEntry(arrayOfByte, aDRS.getTreeHeight()));
    } 
    return ((NodeEntry)linkedList.get(0)).nodeValue;
  }
  
  public boolean verify(byte[] paramArrayOfbyte1, SIG_XMSS[] paramArrayOfSIG_XMSS, byte[] paramArrayOfbyte2, long paramLong, int paramInt, byte[] paramArrayOfbyte3) {
    ADRS aDRS = new ADRS();
    SIG_XMSS sIG_XMSS = paramArrayOfSIG_XMSS[0];
    aDRS.setLayerAddress(0);
    aDRS.setTreeAddress(paramLong);
    byte[] arrayOfByte = xmss_pkFromSig(paramInt, sIG_XMSS, paramArrayOfbyte1, paramArrayOfbyte2, aDRS);
    for (byte b = 1; b < this.engine.D; b++) {
      paramInt = (int)(paramLong & ((1 << this.engine.H_PRIME) - 1));
      paramLong >>>= this.engine.H_PRIME;
      sIG_XMSS = paramArrayOfSIG_XMSS[b];
      aDRS.setLayerAddress(b);
      aDRS.setTreeAddress(paramLong);
      arrayOfByte = xmss_pkFromSig(paramInt, sIG_XMSS, arrayOfByte, paramArrayOfbyte2, aDRS);
    } 
    return Arrays.areEqual(paramArrayOfbyte3, arrayOfByte);
  }
}
