package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.Zuc256CoreEngine;

public final class Zuc256Mac implements Mac {
  private static final int TOPBIT = 128;
  
  private final InternalZuc256Engine theEngine;
  
  private final int theMacLength;
  
  private final int[] theMac;
  
  private final int[] theKeyStream;
  
  private Zuc256CoreEngine theState;
  
  private int theWordIndex;
  
  private int theByteIndex;
  
  public Zuc256Mac(int paramInt) {
    this.theEngine = new InternalZuc256Engine(paramInt);
    this.theMacLength = paramInt;
    int i = paramInt / 32;
    this.theMac = new int[i];
    this.theKeyStream = new int[i + 1];
  }
  
  public String getAlgorithmName() {
    return "Zuc256Mac-" + this.theMacLength;
  }
  
  public int getMacSize() {
    return this.theMacLength / 8;
  }
  
  public void init(CipherParameters paramCipherParameters) {
    this.theEngine.init(true, paramCipherParameters);
    this.theState = (Zuc256CoreEngine)this.theEngine.copy();
    initKeyStream();
  }
  
  private void initKeyStream() {
    byte b;
    for (b = 0; b < this.theMac.length; b++)
      this.theMac[b] = this.theEngine.createKeyStreamWord(); 
    for (b = 0; b < this.theKeyStream.length - 1; b++)
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
  
  private void shift4Final() {
    this.theByteIndex = (this.theByteIndex + 1) % 4;
    if (this.theByteIndex == 0)
      this.theWordIndex = (this.theWordIndex + 1) % this.theKeyStream.length; 
  }
  
  private void updateMac(int paramInt) {
    for (byte b = 0; b < this.theMac.length; b++)
      this.theMac[b] = this.theMac[b] ^ getKeyStreamWord(b, paramInt); 
  }
  
  private int getKeyStreamWord(int paramInt1, int paramInt2) {
    int i = this.theKeyStream[(this.theWordIndex + paramInt1) % this.theKeyStream.length];
    if (paramInt2 == 0)
      return i; 
    int j = this.theKeyStream[(this.theWordIndex + paramInt1 + 1) % this.theKeyStream.length];
    return i << paramInt2 | j >>> 32 - paramInt2;
  }
  
  public void update(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    for (byte b = 0; b < paramInt2; b++)
      update(paramArrayOfbyte[paramInt1 + b]); 
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) {
    shift4Final();
    updateMac(this.theByteIndex * 8);
    for (byte b = 0; b < this.theMac.length; b++)
      Zuc256CoreEngine.encode32be(this.theMac[b], paramArrayOfbyte, paramInt + b * 4); 
    reset();
    return getMacSize();
  }
  
  public void reset() {
    if (this.theState != null)
      this.theEngine.reset(this.theState); 
    initKeyStream();
  }
  
  private static class InternalZuc256Engine extends Zuc256CoreEngine {
    public InternalZuc256Engine(int param1Int) {
      super(param1Int);
    }
    
    int createKeyStreamWord() {
      return makeKeyStreamWord();
    }
  }
}
