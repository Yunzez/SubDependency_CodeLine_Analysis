package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.WeakHashMap;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.ExhaustedPrivateKeyException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class LMSPrivateKeyParameters extends LMSKeyParameters implements LMSContextBasedSigner {
  private static CacheKey T1 = new CacheKey(1);
  
  private static CacheKey[] internedKeys = new CacheKey[129];
  
  private final byte[] I;
  
  private final LMSigParameters parameters;
  
  private final LMOtsParameters otsParameters;
  
  private final int maxQ;
  
  private final byte[] masterSecret;
  
  private final Map<CacheKey, byte[]> tCache;
  
  private final int maxCacheR;
  
  private final Digest tDigest;
  
  private int q;
  
  private LMSPublicKeyParameters publicKey;
  
  public LMSPrivateKeyParameters(LMSigParameters paramLMSigParameters, LMOtsParameters paramLMOtsParameters, int paramInt1, byte[] paramArrayOfbyte1, int paramInt2, byte[] paramArrayOfbyte2) {
    super(true);
    this.parameters = paramLMSigParameters;
    this.otsParameters = paramLMOtsParameters;
    this.q = paramInt1;
    this.I = Arrays.clone(paramArrayOfbyte1);
    this.maxQ = paramInt2;
    this.masterSecret = Arrays.clone(paramArrayOfbyte2);
    this.maxCacheR = 1 << this.parameters.getH() + 1;
    this.tCache = (Map)new WeakHashMap<CacheKey, byte>();
    this.tDigest = DigestUtil.getDigest(paramLMSigParameters.getDigestOID());
  }
  
  private LMSPrivateKeyParameters(LMSPrivateKeyParameters paramLMSPrivateKeyParameters, int paramInt1, int paramInt2) {
    super(true);
    this.parameters = paramLMSPrivateKeyParameters.parameters;
    this.otsParameters = paramLMSPrivateKeyParameters.otsParameters;
    this.q = paramInt1;
    this.I = paramLMSPrivateKeyParameters.I;
    this.maxQ = paramInt2;
    this.masterSecret = paramLMSPrivateKeyParameters.masterSecret;
    this.maxCacheR = 1 << this.parameters.getH();
    this.tCache = paramLMSPrivateKeyParameters.tCache;
    this.tDigest = DigestUtil.getDigest(this.parameters.getDigestOID());
    this.publicKey = paramLMSPrivateKeyParameters.publicKey;
  }
  
  public static LMSPrivateKeyParameters getInstance(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws IOException {
    LMSPrivateKeyParameters lMSPrivateKeyParameters = getInstance(paramArrayOfbyte1);
    lMSPrivateKeyParameters.publicKey = LMSPublicKeyParameters.getInstance(paramArrayOfbyte2);
    return lMSPrivateKeyParameters;
  }
  
  public static LMSPrivateKeyParameters getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof LMSPrivateKeyParameters)
      return (LMSPrivateKeyParameters)paramObject; 
    if (paramObject instanceof DataInputStream) {
      DataInputStream dataInputStream = (DataInputStream)paramObject;
      if (dataInputStream.readInt() != 0)
        throw new IllegalStateException("expected version 0 lms private key"); 
      LMSigParameters lMSigParameters = LMSigParameters.getParametersForType(dataInputStream.readInt());
      LMOtsParameters lMOtsParameters = LMOtsParameters.getParametersForType(dataInputStream.readInt());
      byte[] arrayOfByte1 = new byte[16];
      dataInputStream.readFully(arrayOfByte1);
      int i = dataInputStream.readInt();
      int j = dataInputStream.readInt();
      int k = dataInputStream.readInt();
      if (k < 0)
        throw new IllegalStateException("secret length less than zero"); 
      if (k > dataInputStream.available())
        throw new IOException("secret length exceeded " + dataInputStream.available()); 
      byte[] arrayOfByte2 = new byte[k];
      dataInputStream.readFully(arrayOfByte2);
      return new LMSPrivateKeyParameters(lMSigParameters, lMOtsParameters, i, arrayOfByte1, j, arrayOfByte2);
    } 
    if (paramObject instanceof byte[]) {
      DataInputStream dataInputStream = null;
      try {
        dataInputStream = new DataInputStream(new ByteArrayInputStream((byte[])paramObject));
        return getInstance(dataInputStream);
      } finally {
        if (dataInputStream != null)
          dataInputStream.close(); 
      } 
    } 
    if (paramObject instanceof InputStream)
      return getInstance(Streams.readAll((InputStream)paramObject)); 
    throw new IllegalArgumentException("cannot parse " + paramObject);
  }
  
  LMOtsPrivateKey getCurrentOTSKey() {
    synchronized (this) {
      if (this.q >= this.maxQ)
        throw new ExhaustedPrivateKeyException("ots private keys expired"); 
      return new LMOtsPrivateKey(this.otsParameters, this.I, this.q, this.masterSecret);
    } 
  }
  
  public synchronized int getIndex() {
    return this.q;
  }
  
  synchronized void incIndex() {
    this.q++;
  }
  
  public LMSContext generateLMSContext() {
    LMSigParameters lMSigParameters = getSigParameters();
    int i = lMSigParameters.getH();
    int j = getIndex();
    LMOtsPrivateKey lMOtsPrivateKey = getNextOtsPrivateKey();
    byte b = 0;
    int k = (1 << i) + j;
    byte[][] arrayOfByte = new byte[i][];
    while (b < i) {
      int m = k / (1 << b) ^ 0x1;
      arrayOfByte[b] = findT(m);
      b++;
    } 
    return lMOtsPrivateKey.getSignatureContext(getSigParameters(), arrayOfByte);
  }
  
  public byte[] generateSignature(LMSContext paramLMSContext) {
    try {
      return LMS.generateSign(paramLMSContext).getEncoded();
    } catch (IOException iOException) {
      throw new IllegalStateException("unable to encode signature: " + iOException.getMessage(), iOException);
    } 
  }
  
  LMOtsPrivateKey getNextOtsPrivateKey() {
    synchronized (this) {
      if (this.q >= this.maxQ)
        throw new ExhaustedPrivateKeyException("ots private key exhausted"); 
      LMOtsPrivateKey lMOtsPrivateKey = new LMOtsPrivateKey(this.otsParameters, this.I, this.q, this.masterSecret);
      incIndex();
      return lMOtsPrivateKey;
    } 
  }
  
  public LMSPrivateKeyParameters extractKeyShard(int paramInt) {
    synchronized (this) {
      if (this.q + paramInt >= this.maxQ)
        throw new IllegalArgumentException("usageCount exceeds usages remaining"); 
      LMSPrivateKeyParameters lMSPrivateKeyParameters = new LMSPrivateKeyParameters(this, this.q, this.q + paramInt);
      this.q += paramInt;
      return lMSPrivateKeyParameters;
    } 
  }
  
  public LMSigParameters getSigParameters() {
    return this.parameters;
  }
  
  public LMOtsParameters getOtsParameters() {
    return this.otsParameters;
  }
  
  public byte[] getI() {
    return Arrays.clone(this.I);
  }
  
  public byte[] getMasterSecret() {
    return Arrays.clone(this.masterSecret);
  }
  
  public long getUsagesRemaining() {
    return (this.maxQ - this.q);
  }
  
  public LMSPublicKeyParameters getPublicKey() {
    synchronized (this) {
      if (this.publicKey == null)
        this.publicKey = new LMSPublicKeyParameters(this.parameters, this.otsParameters, findT(T1), this.I); 
      return this.publicKey;
    } 
  }
  
  byte[] findT(int paramInt) {
    return (paramInt < this.maxCacheR) ? findT((paramInt < internedKeys.length) ? internedKeys[paramInt] : new CacheKey(paramInt)) : calcT(paramInt);
  }
  
  private byte[] findT(CacheKey paramCacheKey) {
    synchronized (this.tCache) {
      byte[] arrayOfByte = this.tCache.get(paramCacheKey);
      if (arrayOfByte != null)
        return arrayOfByte; 
      arrayOfByte = calcT(paramCacheKey.index);
      this.tCache.put(paramCacheKey, arrayOfByte);
      return arrayOfByte;
    } 
  }
  
  private byte[] calcT(int paramInt) {
    int i = getSigParameters().getH();
    int j = 1 << i;
    if (paramInt >= j) {
      LmsUtils.byteArray(getI(), this.tDigest);
      LmsUtils.u32str(paramInt, this.tDigest);
      LmsUtils.u16str((short)-32126, this.tDigest);
      byte[] arrayOfByte5 = LM_OTS.lms_ots_generatePublicKey(getOtsParameters(), getI(), paramInt - j, getMasterSecret());
      LmsUtils.byteArray(arrayOfByte5, this.tDigest);
      byte[] arrayOfByte4 = new byte[this.tDigest.getDigestSize()];
      this.tDigest.doFinal(arrayOfByte4, 0);
      return arrayOfByte4;
    } 
    byte[] arrayOfByte2 = findT(2 * paramInt);
    byte[] arrayOfByte3 = findT(2 * paramInt + 1);
    LmsUtils.byteArray(getI(), this.tDigest);
    LmsUtils.u32str(paramInt, this.tDigest);
    LmsUtils.u16str((short)-31869, this.tDigest);
    LmsUtils.byteArray(arrayOfByte2, this.tDigest);
    LmsUtils.byteArray(arrayOfByte3, this.tDigest);
    byte[] arrayOfByte1 = new byte[this.tDigest.getDigestSize()];
    this.tDigest.doFinal(arrayOfByte1, 0);
    return arrayOfByte1;
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    LMSPrivateKeyParameters lMSPrivateKeyParameters = (LMSPrivateKeyParameters)paramObject;
    return (this.q != lMSPrivateKeyParameters.q) ? false : ((this.maxQ != lMSPrivateKeyParameters.maxQ) ? false : (!Arrays.areEqual(this.I, lMSPrivateKeyParameters.I) ? false : (((this.parameters != null) ? !this.parameters.equals(lMSPrivateKeyParameters.parameters) : (lMSPrivateKeyParameters.parameters != null)) ? false : (((this.otsParameters != null) ? !this.otsParameters.equals(lMSPrivateKeyParameters.otsParameters) : (lMSPrivateKeyParameters.otsParameters != null)) ? false : (!Arrays.areEqual(this.masterSecret, lMSPrivateKeyParameters.masterSecret) ? false : ((this.publicKey != null && lMSPrivateKeyParameters.publicKey != null) ? this.publicKey.equals(lMSPrivateKeyParameters.publicKey) : true))))));
  }
  
  public int hashCode() {
    null = this.q;
    null = 31 * null + Arrays.hashCode(this.I);
    null = 31 * null + ((this.parameters != null) ? this.parameters.hashCode() : 0);
    null = 31 * null + ((this.otsParameters != null) ? this.otsParameters.hashCode() : 0);
    null = 31 * null + this.maxQ;
    null = 31 * null + Arrays.hashCode(this.masterSecret);
    return 31 * null + ((this.publicKey != null) ? this.publicKey.hashCode() : 0);
  }
  
  public byte[] getEncoded() throws IOException {
    return Composer.compose().u32str(0).u32str(this.parameters.getType()).u32str(this.otsParameters.getType()).bytes(this.I).u32str(this.q).u32str(this.maxQ).u32str(this.masterSecret.length).bytes(this.masterSecret).build();
  }
  
  static {
    internedKeys[1] = T1;
    for (byte b = 2; b < internedKeys.length; b++)
      internedKeys[b] = new CacheKey(b); 
  }
  
  private static class CacheKey {
    private final int index;
    
    CacheKey(int param1Int) {
      this.index = param1Int;
    }
    
    public int hashCode() {
      return this.index;
    }
    
    public boolean equals(Object param1Object) {
      return (param1Object instanceof CacheKey) ? ((((CacheKey)param1Object).index == this.index)) : false;
    }
  }
}
