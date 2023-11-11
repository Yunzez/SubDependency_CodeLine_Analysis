package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class ChaCha20Poly1305 implements AEADCipher {
  private static final int BUF_SIZE = 64;
  
  private static final int KEY_SIZE = 32;
  
  private static final int NONCE_SIZE = 12;
  
  private static final int MAC_SIZE = 16;
  
  private static final byte[] ZEROES = new byte[15];
  
  private static final long AAD_LIMIT = -1L;
  
  private static final long DATA_LIMIT = 274877906880L;
  
  private final ChaCha7539Engine chacha20;
  
  private final Mac poly1305;
  
  private final byte[] key = new byte[32];
  
  private final byte[] nonce = new byte[12];
  
  private final byte[] buf = new byte[80];
  
  private final byte[] mac = new byte[16];
  
  private byte[] initialAAD;
  
  private long aadCount;
  
  private long dataCount;
  
  private int state = 0;
  
  private int bufPos;
  
  public ChaCha20Poly1305() {
    this(new Poly1305());
  }
  
  public ChaCha20Poly1305(Mac paramMac) {
    if (null == paramMac)
      throw new NullPointerException("'poly1305' cannot be null"); 
    if (16 != paramMac.getMacSize())
      throw new IllegalArgumentException("'poly1305' must be a 128-bit MAC"); 
    this.chacha20 = new ChaCha7539Engine();
    this.poly1305 = paramMac;
  }
  
  public String getAlgorithmName() {
    return "ChaCha20Poly1305";
  }
  
  public void init(boolean paramBoolean, CipherParameters paramCipherParameters) throws IllegalArgumentException {
    KeyParameter keyParameter;
    byte[] arrayOfByte;
    ParametersWithIV parametersWithIV;
    if (paramCipherParameters instanceof AEADParameters) {
      AEADParameters aEADParameters = (AEADParameters)paramCipherParameters;
      int i = aEADParameters.getMacSize();
      if (128 != i)
        throw new IllegalArgumentException("Invalid value for MAC size: " + i); 
      keyParameter = aEADParameters.getKey();
      arrayOfByte = aEADParameters.getNonce();
      parametersWithIV = new ParametersWithIV(keyParameter, arrayOfByte);
      this.initialAAD = aEADParameters.getAssociatedText();
    } else if (paramCipherParameters instanceof ParametersWithIV) {
      ParametersWithIV parametersWithIV1 = (ParametersWithIV)paramCipherParameters;
      keyParameter = (KeyParameter)parametersWithIV1.getParameters();
      arrayOfByte = parametersWithIV1.getIV();
      parametersWithIV = parametersWithIV1;
      this.initialAAD = null;
    } else {
      throw new IllegalArgumentException("invalid parameters passed to ChaCha20Poly1305");
    } 
    if (null == keyParameter) {
      if (0 == this.state)
        throw new IllegalArgumentException("Key must be specified in initial init"); 
    } else if (32 != (keyParameter.getKey()).length) {
      throw new IllegalArgumentException("Key must be 256 bits");
    } 
    if (null == arrayOfByte || 12 != arrayOfByte.length)
      throw new IllegalArgumentException("Nonce must be 96 bits"); 
    if (0 != this.state && paramBoolean && Arrays.areEqual(this.nonce, arrayOfByte) && (null == keyParameter || Arrays.areEqual(this.key, keyParameter.getKey())))
      throw new IllegalArgumentException("cannot reuse nonce for ChaCha20Poly1305 encryption"); 
    if (null != keyParameter)
      System.arraycopy(keyParameter.getKey(), 0, this.key, 0, 32); 
    System.arraycopy(arrayOfByte, 0, this.nonce, 0, 12);
    this.chacha20.init(true, parametersWithIV);
    this.state = paramBoolean ? 1 : 5;
    reset(true, false);
  }
  
  public int getOutputSize(int paramInt) {
    int i = Math.max(0, paramInt) + this.bufPos;
    switch (this.state) {
      case 5:
      case 6:
      case 7:
        return Math.max(0, i - 16);
      case 1:
      case 2:
      case 3:
        return i + 16;
    } 
    throw new IllegalStateException();
  }
  
  public int getUpdateOutputSize(int paramInt) {
    int i = Math.max(0, paramInt) + this.bufPos;
    switch (this.state) {
      case 5:
      case 6:
      case 7:
        i = Math.max(0, i - 16);
      case 1:
      case 2:
      case 3:
        return i - i % 64;
    } 
    throw new IllegalStateException();
  }
  
  public void processAADByte(byte paramByte) {
    checkAAD();
    this.aadCount = incrementCount(this.aadCount, 1, -1L);
    this.poly1305.update(paramByte);
  }
  
  public void processAADBytes(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) {
    if (null == paramArrayOfbyte)
      throw new NullPointerException("'in' cannot be null"); 
    if (paramInt1 < 0)
      throw new IllegalArgumentException("'inOff' cannot be negative"); 
    if (paramInt2 < 0)
      throw new IllegalArgumentException("'len' cannot be negative"); 
    if (paramInt1 > paramArrayOfbyte.length - paramInt2)
      throw new DataLengthException("Input buffer too short"); 
    checkAAD();
    if (paramInt2 > 0) {
      this.aadCount = incrementCount(this.aadCount, paramInt2, -1L);
      this.poly1305.update(paramArrayOfbyte, paramInt1, paramInt2);
    } 
  }
  
  public int processByte(byte paramByte, byte[] paramArrayOfbyte, int paramInt) throws DataLengthException {
    checkData();
    switch (this.state) {
      case 7:
        this.buf[this.bufPos] = paramByte;
        if (++this.bufPos == this.buf.length) {
          this.poly1305.update(this.buf, 0, 64);
          processData(this.buf, 0, 64, paramArrayOfbyte, paramInt);
          System.arraycopy(this.buf, 64, this.buf, 0, 16);
          this.bufPos = 16;
          return 64;
        } 
        return 0;
      case 3:
        this.buf[this.bufPos] = paramByte;
        if (++this.bufPos == 64) {
          processData(this.buf, 0, 64, paramArrayOfbyte, paramInt);
          this.poly1305.update(paramArrayOfbyte, paramInt, 64);
          this.bufPos = 0;
          return 64;
        } 
        return 0;
    } 
    throw new IllegalStateException();
  }
  
  public int processBytes(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) throws DataLengthException {
    // Byte code:
    //   0: aconst_null
    //   1: aload_1
    //   2: if_acmpne -> 15
    //   5: new java/lang/NullPointerException
    //   8: dup
    //   9: ldc ''in' cannot be null'
    //   11: invokespecial <init> : (Ljava/lang/String;)V
    //   14: athrow
    //   15: aconst_null
    //   16: aload #4
    //   18: if_acmpne -> 21
    //   21: iload_2
    //   22: ifge -> 35
    //   25: new java/lang/IllegalArgumentException
    //   28: dup
    //   29: ldc ''inOff' cannot be negative'
    //   31: invokespecial <init> : (Ljava/lang/String;)V
    //   34: athrow
    //   35: iload_3
    //   36: ifge -> 49
    //   39: new java/lang/IllegalArgumentException
    //   42: dup
    //   43: ldc ''len' cannot be negative'
    //   45: invokespecial <init> : (Ljava/lang/String;)V
    //   48: athrow
    //   49: iload_2
    //   50: aload_1
    //   51: arraylength
    //   52: iload_3
    //   53: isub
    //   54: if_icmple -> 67
    //   57: new org/bouncycastle/crypto/DataLengthException
    //   60: dup
    //   61: ldc 'Input buffer too short'
    //   63: invokespecial <init> : (Ljava/lang/String;)V
    //   66: athrow
    //   67: iload #5
    //   69: ifge -> 82
    //   72: new java/lang/IllegalArgumentException
    //   75: dup
    //   76: ldc ''outOff' cannot be negative'
    //   78: invokespecial <init> : (Ljava/lang/String;)V
    //   81: athrow
    //   82: aload_0
    //   83: invokespecial checkData : ()V
    //   86: iconst_0
    //   87: istore #6
    //   89: aload_0
    //   90: getfield state : I
    //   93: lookupswitch default -> 392, 3 -> 231, 7 -> 120
    //   120: iconst_0
    //   121: istore #7
    //   123: iload #7
    //   125: iload_3
    //   126: if_icmpge -> 228
    //   129: aload_0
    //   130: getfield buf : [B
    //   133: aload_0
    //   134: getfield bufPos : I
    //   137: aload_1
    //   138: iload_2
    //   139: iload #7
    //   141: iadd
    //   142: baload
    //   143: bastore
    //   144: aload_0
    //   145: dup
    //   146: getfield bufPos : I
    //   149: iconst_1
    //   150: iadd
    //   151: dup_x1
    //   152: putfield bufPos : I
    //   155: aload_0
    //   156: getfield buf : [B
    //   159: arraylength
    //   160: if_icmpne -> 222
    //   163: aload_0
    //   164: getfield poly1305 : Lorg/bouncycastle/crypto/Mac;
    //   167: aload_0
    //   168: getfield buf : [B
    //   171: iconst_0
    //   172: bipush #64
    //   174: invokeinterface update : ([BII)V
    //   179: aload_0
    //   180: aload_0
    //   181: getfield buf : [B
    //   184: iconst_0
    //   185: bipush #64
    //   187: aload #4
    //   189: iload #5
    //   191: iload #6
    //   193: iadd
    //   194: invokespecial processData : ([BII[BI)V
    //   197: aload_0
    //   198: getfield buf : [B
    //   201: bipush #64
    //   203: aload_0
    //   204: getfield buf : [B
    //   207: iconst_0
    //   208: bipush #16
    //   210: invokestatic arraycopy : (Ljava/lang/Object;ILjava/lang/Object;II)V
    //   213: aload_0
    //   214: bipush #16
    //   216: putfield bufPos : I
    //   219: iinc #6, 64
    //   222: iinc #7, 1
    //   225: goto -> 123
    //   228: goto -> 400
    //   231: aload_0
    //   232: getfield bufPos : I
    //   235: ifeq -> 318
    //   238: iload_3
    //   239: ifle -> 318
    //   242: iinc #3, -1
    //   245: aload_0
    //   246: getfield buf : [B
    //   249: aload_0
    //   250: getfield bufPos : I
    //   253: aload_1
    //   254: iload_2
    //   255: iinc #2, 1
    //   258: baload
    //   259: bastore
    //   260: aload_0
    //   261: dup
    //   262: getfield bufPos : I
    //   265: iconst_1
    //   266: iadd
    //   267: dup_x1
    //   268: putfield bufPos : I
    //   271: bipush #64
    //   273: if_icmpne -> 238
    //   276: aload_0
    //   277: aload_0
    //   278: getfield buf : [B
    //   281: iconst_0
    //   282: bipush #64
    //   284: aload #4
    //   286: iload #5
    //   288: invokespecial processData : ([BII[BI)V
    //   291: aload_0
    //   292: getfield poly1305 : Lorg/bouncycastle/crypto/Mac;
    //   295: aload #4
    //   297: iload #5
    //   299: bipush #64
    //   301: invokeinterface update : ([BII)V
    //   306: aload_0
    //   307: iconst_0
    //   308: putfield bufPos : I
    //   311: bipush #64
    //   313: istore #6
    //   315: goto -> 318
    //   318: iload_3
    //   319: bipush #64
    //   321: if_icmplt -> 369
    //   324: aload_0
    //   325: aload_1
    //   326: iload_2
    //   327: bipush #64
    //   329: aload #4
    //   331: iload #5
    //   333: iload #6
    //   335: iadd
    //   336: invokespecial processData : ([BII[BI)V
    //   339: aload_0
    //   340: getfield poly1305 : Lorg/bouncycastle/crypto/Mac;
    //   343: aload #4
    //   345: iload #5
    //   347: iload #6
    //   349: iadd
    //   350: bipush #64
    //   352: invokeinterface update : ([BII)V
    //   357: iinc #2, 64
    //   360: iinc #3, -64
    //   363: iinc #6, 64
    //   366: goto -> 318
    //   369: iload_3
    //   370: ifle -> 400
    //   373: aload_1
    //   374: iload_2
    //   375: aload_0
    //   376: getfield buf : [B
    //   379: iconst_0
    //   380: iload_3
    //   381: invokestatic arraycopy : (Ljava/lang/Object;ILjava/lang/Object;II)V
    //   384: aload_0
    //   385: iload_3
    //   386: putfield bufPos : I
    //   389: goto -> 400
    //   392: new java/lang/IllegalStateException
    //   395: dup
    //   396: invokespecial <init> : ()V
    //   399: athrow
    //   400: iload #6
    //   402: ireturn
  }
  
  public int doFinal(byte[] paramArrayOfbyte, int paramInt) throws IllegalStateException, InvalidCipherTextException {
    if (null == paramArrayOfbyte)
      throw new NullPointerException("'out' cannot be null"); 
    if (paramInt < 0)
      throw new IllegalArgumentException("'outOff' cannot be negative"); 
    checkData();
    Arrays.clear(this.mac);
    int i = 0;
    switch (this.state) {
      case 7:
        if (this.bufPos < 16)
          throw new InvalidCipherTextException("data too short"); 
        i = this.bufPos - 16;
        if (paramInt > paramArrayOfbyte.length - i)
          throw new OutputLengthException("Output buffer too short"); 
        if (i > 0) {
          this.poly1305.update(this.buf, 0, i);
          processData(this.buf, 0, i, paramArrayOfbyte, paramInt);
        } 
        finishData(8);
        if (!Arrays.constantTimeAreEqual(16, this.mac, 0, this.buf, i))
          throw new InvalidCipherTextException("mac check in ChaCha20Poly1305 failed"); 
        reset(false, true);
        return i;
      case 3:
        i = this.bufPos + 16;
        if (paramInt > paramArrayOfbyte.length - i)
          throw new OutputLengthException("Output buffer too short"); 
        if (this.bufPos > 0) {
          processData(this.buf, 0, this.bufPos, paramArrayOfbyte, paramInt);
          this.poly1305.update(paramArrayOfbyte, paramInt, this.bufPos);
        } 
        finishData(4);
        System.arraycopy(this.mac, 0, paramArrayOfbyte, paramInt + this.bufPos, 16);
        reset(false, true);
        return i;
    } 
    throw new IllegalStateException();
  }
  
  public byte[] getMac() {
    return Arrays.clone(this.mac);
  }
  
  public void reset() {
    reset(true, true);
  }
  
  private void checkAAD() {
    switch (this.state) {
      case 5:
        this.state = 6;
      case 1:
        this.state = 2;
      case 2:
      case 6:
        return;
      case 4:
        throw new IllegalStateException("ChaCha20Poly1305 cannot be reused for encryption");
    } 
    throw new IllegalStateException();
  }
  
  private void checkData() {
    switch (this.state) {
      case 5:
      case 6:
        finishAAD(7);
      case 1:
      case 2:
        finishAAD(3);
      case 3:
      case 7:
        return;
      case 4:
        throw new IllegalStateException("ChaCha20Poly1305 cannot be reused for encryption");
    } 
    throw new IllegalStateException();
  }
  
  private void finishAAD(int paramInt) {
    padMAC(this.aadCount);
    this.state = paramInt;
  }
  
  private void finishData(int paramInt) {
    padMAC(this.dataCount);
    byte[] arrayOfByte = new byte[16];
    Pack.longToLittleEndian(this.aadCount, arrayOfByte, 0);
    Pack.longToLittleEndian(this.dataCount, arrayOfByte, 8);
    this.poly1305.update(arrayOfByte, 0, 16);
    this.poly1305.doFinal(this.mac, 0);
    this.state = paramInt;
  }
  
  private long incrementCount(long paramLong1, int paramInt, long paramLong2) {
    if (paramLong1 + Long.MIN_VALUE > paramLong2 - paramInt + Long.MIN_VALUE)
      throw new IllegalStateException("Limit exceeded"); 
    return paramLong1 + paramInt;
  }
  
  private void initMAC() {
    byte[] arrayOfByte = new byte[64];
    try {
      this.chacha20.processBytes(arrayOfByte, 0, 64, arrayOfByte, 0);
      this.poly1305.init(new KeyParameter(arrayOfByte, 0, 32));
    } finally {
      Arrays.clear(arrayOfByte);
    } 
  }
  
  private void padMAC(long paramLong) {
    int i = (int)paramLong & 0xF;
    if (0 != i)
      this.poly1305.update(ZEROES, 0, 16 - i); 
  }
  
  private void processData(byte[] paramArrayOfbyte1, int paramInt1, int paramInt2, byte[] paramArrayOfbyte2, int paramInt3) {
    if (paramInt3 > paramArrayOfbyte2.length - paramInt2)
      throw new OutputLengthException("Output buffer too short"); 
    this.chacha20.processBytes(paramArrayOfbyte1, paramInt1, paramInt2, paramArrayOfbyte2, paramInt3);
    this.dataCount = incrementCount(this.dataCount, paramInt2, 274877906880L);
  }
  
  private void reset(boolean paramBoolean1, boolean paramBoolean2) {
    Arrays.clear(this.buf);
    if (paramBoolean1)
      Arrays.clear(this.mac); 
    this.aadCount = 0L;
    this.dataCount = 0L;
    this.bufPos = 0;
    switch (this.state) {
      case 1:
      case 5:
        break;
      case 6:
      case 7:
      case 8:
        this.state = 5;
        break;
      case 2:
      case 3:
      case 4:
        this.state = 4;
        return;
      default:
        throw new IllegalStateException();
    } 
    if (paramBoolean2)
      this.chacha20.reset(); 
    initMAC();
    if (null != this.initialAAD)
      processAADBytes(this.initialAAD, 0, this.initialAAD.length); 
  }
  
  private static final class State {
    static final int UNINITIALIZED = 0;
    
    static final int ENC_INIT = 1;
    
    static final int ENC_AAD = 2;
    
    static final int ENC_DATA = 3;
    
    static final int ENC_FINAL = 4;
    
    static final int DEC_INIT = 5;
    
    static final int DEC_AAD = 6;
    
    static final int DEC_DATA = 7;
    
    static final int DEC_FINAL = 8;
  }
}
