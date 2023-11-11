package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
import org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class GCMSIVBlockCipher implements AEADBlockCipher {
  private static final int BUFLEN = 16;
  
  private static final int HALFBUFLEN = 8;
  
  private static final int NONCELEN = 12;
  
  private static final int MAX_DATALEN = 2147483623;
  
  private static final byte MASK = -128;
  
  private static final byte ADD = -31;
  
  private static final int INIT = 1;
  
  private static final int AEAD_COMPLETE = 2;
  
  private final BlockCipher theCipher;
  
  private final GCMMultiplier theMultiplier;
  
  private final byte[] theGHash = new byte[16];
  
  private final byte[] theReverse = new byte[16];
  
  private final GCMSIVHasher theAEADHasher;
  
  private final GCMSIVHasher theDataHasher;
  
  private GCMSIVCache thePlain;
  
  private GCMSIVCache theEncData;
  
  private boolean forEncryption;
  
  private byte[] theInitialAEAD;
  
  private byte[] theNonce;
  
  private int theFlags;
  
  private byte[] macBlock = new byte[16];
  
  public GCMSIVBlockCipher() {
    this(new AESEngine());
  }
  
  public GCMSIVBlockCipher(BlockCipher paramBlockCipher) {
    this(paramBlockCipher, new Tables4kGCMMultiplier());
  }
  
  public GCMSIVBlockCipher(BlockCipher paramBlockCipher, GCMMultiplier paramGCMMultiplier) {
    if (paramBlockCipher.getBlockSize() != 16)
      throw new IllegalArgumentException("Cipher required with a block size of 16."); 
    this.theCipher = paramBlockCipher;
    this.theMultiplier = paramGCMMultiplier;
    this.theAEADHasher = new GCMSIVHasher();
    this.theDataHasher = new GCMSIVHasher();
  }
  
  public BlockCipher getUnderlyingCipher() {
    return this.theCipher;
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) throws IllegalArgumentException {
    byte[] arrayOfByte1 = null;
    byte[] arrayOfByte2 = null;
    KeyParameter keyParameter = null;
    if (paramCipherParameters instanceof AEADParameters) {
      AEADParameters aEADParameters = (AEADParameters)paramCipherParameters;
      arrayOfByte1 = aEADParameters.getAssociatedText();
      arrayOfByte2 = aEADParameters.getNonce();
      keyParameter = aEADParameters.getKey();
    } else if (paramCipherParameters instanceof ParametersWithIV) {
      ParametersWithIV parametersWithIV = (ParametersWithIV)paramCipherParameters;
      arrayOfByte2 = parametersWithIV.getIV();
      keyParameter = (KeyParameter)parametersWithIV.getParameters();
    } else {
      throw new IllegalArgumentException("invalid parameters passed to GCM-SIV");
    } 
    if (arrayOfByte2 == null || arrayOfByte2.length != 12)
      throw new IllegalArgumentException("Invalid nonce"); 
    if (keyParameter == null || ((keyParameter.getKey()).length != 16 && (keyParameter.getKey()).length != 32))
      throw new IllegalArgumentException("Invalid key"); 
    this.forEncryption = paramBoolean;
    this.theInitialAEAD = arrayOfByte1;
    this.theNonce = arrayOfByte2;
    deriveKeys(keyParameter);
    resetStreams();
  }
  
  public String getAlgorithmName() {
    return this.theCipher.getAlgorithmName() + "-GCM-SIV";
  }
  
  private void checkAEADStatus(int paramInt) {
    if ((this.theFlags & 0x1) == 0)
      throw new IllegalStateException("Cipher is not initialised"); 
    if ((this.theFlags & 0x2) != 0)
      throw new IllegalStateException("AEAD data cannot be processed after ordinary data"); 
    if (this.theAEADHasher.getBytesProcessed() + Long.MIN_VALUE > (2147483623 - paramInt) + Long.MIN_VALUE)
      throw new IllegalStateException("AEAD byte count exceeded"); 
  }
  
  private void checkStatus(int paramInt) {
    if ((this.theFlags & 0x1) == 0)
      throw new IllegalStateException("Cipher is not initialised"); 
    if ((this.theFlags & 0x2) == 0) {
      this.theAEADHasher.completeHash();
      this.theFlags |= 0x2;
    } 
    long l1 = 2147483623L;
    long l2 = this.thePlain.size();
    if (!this.forEncryption) {
      l1 += 16L;
      l2 = this.theEncData.size();
    } 
    if (l2 + Long.MIN_VALUE > l1 - paramInt + Long.MIN_VALUE)
      throw new IllegalStateException("byte count exceeded"); 
  }
  
  public void processAADByte(byte paramByte) {
    checkAEADStatus(1);
    this.theAEADHasher.updateHash(paramByte);
  }
  
  public void processAADBytes(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    checkAEADStatus(paramInt2);
    checkBuffer(paramArrayOfbyte, paramInt1, paramInt2, false);
    this.theAEADHasher.updateHash(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  public int processByte(byte paramByte, byte[] paramArrayOfbyte, int paramInt) throws DataLengthException {
    checkStatus(1);
    if (this.forEncryption) {
      this.thePlain.write(paramByte);
      this.theDataHasher.updateHash(paramByte);
    } else {
      this.theEncData.write(paramByte);
    } 
    return 0;
  }
  
  public int processBytes(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws DataLengthException {
    checkStatus(paramInt2);
    checkBuffer(paramArrayOfbyte1, paramInt1, paramInt2, false);
    if (this.forEncryption) {
      this.thePlain.write(paramArrayOfbyte1, paramInt1, paramInt2);
      this.theDataHasher.updateHash(paramArrayOfbyte1, paramInt1, paramInt2);
    } else {
      this.theEncData.write(paramArrayOfbyte1, paramInt1, paramInt2);
    } 
    return 0;
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) throws IllegalStateException, InvalidCipherTextException {
    checkStatus(0);
    checkBuffer(paramArrayOfbyte, paramInt, getOutputSize(0), true);
    if (this.forEncryption) {
      byte[] arrayOfByte1 = calculateTag();
      int j = 16 + encryptPlain(arrayOfByte1, paramArrayOfbyte, paramInt);
      System.arraycopy(arrayOfByte1, 0, paramArrayOfbyte, paramInt + this.thePlain.size(), 16);
      System.arraycopy(arrayOfByte1, 0, this.macBlock, 0, this.macBlock.length);
      resetStreams();
      return j;
    } 
    decryptPlain();
    int i = this.thePlain.size();
    byte[] arrayOfByte = this.thePlain.getBuffer();
    System.arraycopy(arrayOfByte, 0, paramArrayOfbyte, paramInt, i);
    resetStreams();
    return i;
  }
  
  public byte[] getMac() {
    return Arrays.clone(this.macBlock);
  }
  
  public int getUpdateOutputSize(int paramInt) {
    return 0;
  }
  
  public int getOutputSize(int paramInt) {
    if (this.forEncryption)
      return paramInt + this.thePlain.size() + 16; 
    int i = paramInt + this.theEncData.size();
    return (i > 16) ? (i - 16) : 0;
  }
  
  public void reset() {
    resetStreams();
  }
  
  private void resetStreams() {
    if (this.thePlain != null)
      this.thePlain.clearBuffer(); 
    this.theAEADHasher.reset();
    this.theDataHasher.reset();
    this.thePlain = new GCMSIVCache();
    this.theEncData = this.forEncryption ? null : new GCMSIVCache();
    this.theFlags &= 0xFFFFFFFD;
    Arrays.fill(this.theGHash, (byte)0);
    if (this.theInitialAEAD != null)
      this.theAEADHasher.updateHash(this.theInitialAEAD, 0, this.theInitialAEAD.length); 
  }
  
  private static int bufLength(byte[] paramArrayOfbyte) {
    return (paramArrayOfbyte == null) ? 0 : paramArrayOfbyte.length;
  }
  
  private static void checkBuffer(byte[] paramArrayOfbyte, int paramInt1, int paramInt2, boolean paramBoolean) {
    int i = bufLength(paramArrayOfbyte);
    int j = paramInt1 + paramInt2;
    boolean bool = (paramInt2 < 0 || paramInt1 < 0 || j < 0) ? true : false;
    if (bool || j > i)
      throw paramBoolean ? new OutputLengthException("Output buffer too short.") : new DataLengthException("Input buffer too short."); 
  }
  
  private int encryptPlain(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt) {
    byte[] arrayOfByte1 = this.thePlain.getBuffer();
    byte[] arrayOfByte2 = Arrays.clone(paramArrayOfbyte1);
    arrayOfByte2[15] = (byte)(arrayOfByte2[15] | Byte.MIN_VALUE);
    byte[] arrayOfByte3 = new byte[16];
    int i = this.thePlain.size();
    int j = 0;
    while (i > 0) {
      this.theCipher.processBlock(arrayOfByte2, 0, arrayOfByte3, 0);
      int k = Math.min(16, i);
      xorBlock(arrayOfByte3, arrayOfByte1, j, k);
      System.arraycopy(arrayOfByte3, 0, paramArrayOfbyte2, paramInt + j, k);
      i -= k;
      j += k;
      incrementCounter(arrayOfByte2);
    } 
    return this.thePlain.size();
  }
  
  private void decryptPlain() throws InvalidCipherTextException {
    byte[] arrayOfByte1 = this.theEncData.getBuffer();
    int i = this.theEncData.size() - 16;
    if (i < 0)
      throw new InvalidCipherTextException("Data too short"); 
    byte[] arrayOfByte2 = Arrays.copyOfRange(arrayOfByte1, i, i + 16);
    byte[] arrayOfByte3 = Arrays.clone(arrayOfByte2);
    arrayOfByte3[15] = (byte)(arrayOfByte3[15] | Byte.MIN_VALUE);
    byte[] arrayOfByte4 = new byte[16];
    int j = 0;
    while (i > 0) {
      this.theCipher.processBlock(arrayOfByte3, 0, arrayOfByte4, 0);
      int k = Math.min(16, i);
      xorBlock(arrayOfByte4, arrayOfByte1, j, k);
      this.thePlain.write(arrayOfByte4, 0, k);
      this.theDataHasher.updateHash(arrayOfByte4, 0, k);
      i -= k;
      j += k;
      incrementCounter(arrayOfByte3);
    } 
    byte[] arrayOfByte5 = calculateTag();
    if (!Arrays.constantTimeAreEqual(arrayOfByte5, arrayOfByte2)) {
      reset();
      throw new InvalidCipherTextException("mac check failed");
    } 
    System.arraycopy(arrayOfByte5, 0, this.macBlock, 0, this.macBlock.length);
  }
  
  private byte[] calculateTag() {
    this.theDataHasher.completeHash();
    byte[] arrayOfByte1 = completePolyVal();
    byte[] arrayOfByte2 = new byte[16];
    for (byte b = 0; b < 12; b++)
      arrayOfByte1[b] = (byte)(arrayOfByte1[b] ^ this.theNonce[b]); 
    arrayOfByte1[15] = (byte)(arrayOfByte1[15] & 0xFFFFFF7F);
    this.theCipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
    return arrayOfByte2;
  }
  
  private byte[] completePolyVal() {
    byte[] arrayOfByte = new byte[16];
    gHashLengths();
    fillReverse(this.theGHash, 0, 16, arrayOfByte);
    return arrayOfByte;
  }
  
  private void gHashLengths() {
    byte[] arrayOfByte = new byte[16];
    Pack.longToBigEndian(8L * this.theDataHasher.getBytesProcessed(), arrayOfByte, 0);
    Pack.longToBigEndian(8L * this.theAEADHasher.getBytesProcessed(), arrayOfByte, 8);
    gHASH(arrayOfByte);
  }
  
  private void gHASH(byte[] paramArrayOfbyte) {
    xorBlock(this.theGHash, paramArrayOfbyte);
    this.theMultiplier.multiplyH(this.theGHash);
  }
  
  private static void fillReverse(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2) {
    byte b1 = 0;
    for (byte b2 = 15; b1 < paramInt2; b2--) {
      paramArrayOfbyte2[b2] = paramArrayOfbyte1[paramInt1 + b1];
      b1++;
    } 
  }
  
  private static void xorBlock(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    for (byte b = 0; b < 16; b++)
      paramArrayOfbyte1[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]); 
  }
  
  private static void xorBlock(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt1, int paramInt2) {
    for (byte b = 0; b < paramInt2; b++)
      paramArrayOfbyte1[b] = (byte)(paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b + paramInt1]); 
  }
  
  private static void incrementCounter(byte[] paramArrayOfbyte) {
    byte b = 0;
    paramArrayOfbyte[b] = (byte)(paramArrayOfbyte[b] + 1);
    while (b < 4 && (byte)(paramArrayOfbyte[b] + 1) == 0)
      b++; 
  }
  
  private static void mulX(byte[] paramArrayOfbyte) {
    boolean bool = false;
    for (byte b = 0; b < 16; b++) {
      byte b1 = paramArrayOfbyte[b];
      paramArrayOfbyte[b] = (byte)(b1 >> 1 & 0x7F | bool);
      bool = ((b1 & 0x1) == 0) ? false : true;
    } 
    if (bool)
      paramArrayOfbyte[0] = (byte)(paramArrayOfbyte[0] ^ 0xFFFFFFE1); 
  }
  
  private void deriveKeys(KeyParameter paramKeyParameter) {
    byte[] arrayOfByte1 = new byte[16];
    byte[] arrayOfByte2 = new byte[16];
    byte[] arrayOfByte3 = new byte[16];
    byte[] arrayOfByte4 = new byte[(paramKeyParameter.getKey()).length];
    System.arraycopy(this.theNonce, 0, arrayOfByte1, 4, 12);
    this.theCipher.init(true, paramKeyParameter);
    boolean bool = false;
    this.theCipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
    System.arraycopy(arrayOfByte2, 0, arrayOfByte3, bool, 8);
    arrayOfByte1[0] = (byte)(arrayOfByte1[0] + 1);
    bool += true;
    this.theCipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
    System.arraycopy(arrayOfByte2, 0, arrayOfByte3, bool, 8);
    arrayOfByte1[0] = (byte)(arrayOfByte1[0] + 1);
    bool = false;
    this.theCipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
    System.arraycopy(arrayOfByte2, 0, arrayOfByte4, bool, 8);
    arrayOfByte1[0] = (byte)(arrayOfByte1[0] + 1);
    bool += true;
    this.theCipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
    System.arraycopy(arrayOfByte2, 0, arrayOfByte4, bool, 8);
    if (arrayOfByte4.length == 32) {
      arrayOfByte1[0] = (byte)(arrayOfByte1[0] + 1);
      bool += true;
      this.theCipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
      System.arraycopy(arrayOfByte2, 0, arrayOfByte4, bool, 8);
      arrayOfByte1[0] = (byte)(arrayOfByte1[0] + 1);
      bool += true;
      this.theCipher.processBlock(arrayOfByte1, 0, arrayOfByte2, 0);
      System.arraycopy(arrayOfByte2, 0, arrayOfByte4, bool, 8);
    } 
    this.theCipher.init(true, new KeyParameter(arrayOfByte4));
    fillReverse(arrayOfByte3, 0, 16, arrayOfByte2);
    mulX(arrayOfByte2);
    this.theMultiplier.init(arrayOfByte2);
    this.theFlags |= 0x1;
  }
  
  private static class GCMSIVCache extends ByteArrayOutputStream {
    byte[] getBuffer() {
      return this.buf;
    }
    
    void clearBuffer() {
      Arrays.fill(getBuffer(), (byte)0);
    }
  }
  
  private class GCMSIVHasher {
    private final byte[] theBuffer = new byte[16];
    
    private final byte[] theByte = new byte[1];
    
    private int numActive;
    
    private long numHashed;
    
    private GCMSIVHasher() {}
    
    long getBytesProcessed() {
      return this.numHashed;
    }
    
    void reset() {
      this.numActive = 0;
      this.numHashed = 0L;
    }
    
    void updateHash(byte param1Byte) {
      this.theByte[0] = param1Byte;
      updateHash(this.theByte, 0, 1);
    }
    
    void updateHash(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      int i = 16 - this.numActive;
      int j = 0;
      int k = param1Int2;
      if (this.numActive > 0 && param1Int2 >= i) {
        System.arraycopy(param1ArrayOfbyte, param1Int1, this.theBuffer, this.numActive, i);
        GCMSIVBlockCipher.fillReverse(this.theBuffer, 0, 16, GCMSIVBlockCipher.this.theReverse);
        GCMSIVBlockCipher.this.gHASH(GCMSIVBlockCipher.this.theReverse);
        j += i;
        k -= i;
        this.numActive = 0;
      } 
      while (k >= 16) {
        GCMSIVBlockCipher.fillReverse(param1ArrayOfbyte, param1Int1 + j, 16, GCMSIVBlockCipher.this.theReverse);
        GCMSIVBlockCipher.this.gHASH(GCMSIVBlockCipher.this.theReverse);
        j += i;
        k -= i;
      } 
      if (k > 0) {
        System.arraycopy(param1ArrayOfbyte, param1Int1 + j, this.theBuffer, this.numActive, k);
        this.numActive += k;
      } 
      this.numHashed += param1Int2;
    }
    
    void completeHash() {
      if (this.numActive > 0) {
        Arrays.fill(GCMSIVBlockCipher.this.theReverse, (byte)0);
        GCMSIVBlockCipher.fillReverse(this.theBuffer, 0, this.numActive, GCMSIVBlockCipher.this.theReverse);
        GCMSIVBlockCipher.this.gHASH(GCMSIVBlockCipher.this.theReverse);
      } 
    }
  }
}
