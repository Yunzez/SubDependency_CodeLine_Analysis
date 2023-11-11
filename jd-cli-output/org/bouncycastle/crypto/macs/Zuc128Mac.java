package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.Zuc128CoreEngine;

public final class Zuc128Mac implements Mac {
  private static final int TOPBIT = 128;
  
  private final InternalZuc128Engine theEngine = new InternalZuc128Engine();
  
  private int theMac;
  
  private final int[] theKeyStream = new int[2];
  
  private Zuc128CoreEngine theState;
  
  private int theWordIndex;
  
  private int theByteIndex;
  
  public String getAlgorithmName() {
    return "Zuc128Mac";
  }
  
  public int getMacSize() {
    return 4;
  }
  
  public void init(CipherParameters paramCipherParameters) {
    this.theEngine.init(true, paramCipherParameters);
    this.theState = (Zuc128CoreEngine)this.theEngine.copy();
    initKeyStream();
  }
  
  private void initKeyStream() {
    this.theMac = 0;
    for (byte b = 0; b < this.theKeyStream.length - 1; b++)
      this.theKeyStream[b] = this.theEngine.createKeyStreamWord(); 
    this.theWordIndex = this.theKeyStream.length - 1;
    this.theByteIndex = 3;
  }
  
  public void update(byte paramByte) {
    shift4NextByte();
    int i = this.theByteIndex * 8;
    int j = 128;
    for (byte b = 0; j > 0; b++) {
      if ((paramByte & j) != 0)
        updateMac(i + b); 
      j >>= 1;
    } 
  }
  
  private void shift4NextByte() {
    this.theByteIndex = (this.theByteIndex + 1) % 4;
    if (this.theByteIndex == 0) {
      this.theKeyStream[this.theWordIndex] = this.theEngine.createKeyStreamWord();
      this.theWordIndex = (this.theWordIndex + 1) % this.theKeyStream.length;
    } 
  }
  
  private void updateMac(int paramInt) {
    this.theMac ^= getKeyStreamWord(paramInt);
  }
  
  private int getKeyStreamWord(int paramInt) {
    int i = this.theKeyStream[this.theWordIndex];
    if (paramInt == 0)
      return i; 
    int j = this.theKeyStream[(this.theWordIndex + 1) % this.theKeyStream.length];
    return i << paramInt | j >>> 32 - paramInt;
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    for (byte b = 0; b < paramInt2; b++)
      update(paramArrayOfbyte[paramInt1 + b]); 
  }
  
  private int getFinalWord() {
    if (this.theByteIndex != 0)
      return this.theEngine.createKeyStreamWord(); 
    this.theWordIndex = (this.theWordIndex + 1) % this.theKeyStream.length;
    return this.theKeyStream[this.theWordIndex];
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    shift4NextByte();
    this.theMac ^= getKeyStreamWord(this.theByteIndex * 8);
    this.theMac ^= getFinalWord();
    Zuc128CoreEngine.encode32be(this.theMac, paramArrayOfbyte, paramInt);
    reset();
    return getMacSize();
  }
  
  public void reset() {
    if (this.theState != null)
      this.theEngine.reset(this.theState); 
    initKeyStream();
  }
  
  private static class InternalZuc128Engine extends Zuc128CoreEngine {
    private InternalZuc128Engine() {}
    
    int createKeyStreamWord() {
      return makeKeyStreamWord();
    }
  }
}
