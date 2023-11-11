package org.bouncycastle.pqc.crypto.lms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

public class HSSPrivateKeyParameters extends LMSKeyParameters implements LMSContextBasedSigner {
  private final int l;
  
  private final boolean isShard;
  
  private List<LMSPrivateKeyParameters> keys;
  
  private List<LMSSignature> sig;
  
  private final long indexLimit;
  
  private long index = 0L;
  
  private HSSPublicKeyParameters publicKey;
  
  public HSSPrivateKeyParameters(int paramInt, List<LMSPrivateKeyParameters> paramList, List<LMSSignature> paramList1, long paramLong1, long paramLong2) {
    super(true);
    this.l = paramInt;
    this.keys = Collections.unmodifiableList(paramList);
    this.sig = Collections.unmodifiableList(paramList1);
    this.index = paramLong1;
    this.indexLimit = paramLong2;
    this.isShard = false;
    resetKeyToIndex();
  }
  
  private HSSPrivateKeyParameters(int paramInt, List<LMSPrivateKeyParameters> paramList, List<LMSSignature> paramList1, long paramLong1, long paramLong2, boolean paramBoolean) {
    super(true);
    this.l = paramInt;
    this.keys = Collections.unmodifiableList(paramList);
    this.sig = Collections.unmodifiableList(paramList1);
    this.index = paramLong1;
    this.indexLimit = paramLong2;
    this.isShard = paramBoolean;
  }
  
  public static HSSPrivateKeyParameters getInstance(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws IOException {
    HSSPrivateKeyParameters hSSPrivateKeyParameters = getInstance(paramArrayOfbyte1);
    hSSPrivateKeyParameters.publicKey = HSSPublicKeyParameters.getInstance(paramArrayOfbyte2);
    return hSSPrivateKeyParameters;
  }
  
  public static HSSPrivateKeyParameters getInstance(Object paramObject) throws IOException {
    if (paramObject instanceof HSSPrivateKeyParameters)
      return (HSSPrivateKeyParameters)paramObject; 
    if (paramObject instanceof DataInputStream) {
      if (((DataInputStream)paramObject).readInt() != 0)
        throw new IllegalStateException("unknown version for hss private key"); 
      int i = ((DataInputStream)paramObject).readInt();
      long l1 = ((DataInputStream)paramObject).readLong();
      long l2 = ((DataInputStream)paramObject).readLong();
      boolean bool = ((DataInputStream)paramObject).readBoolean();
      ArrayList<LMSPrivateKeyParameters> arrayList = new ArrayList();
      ArrayList<LMSSignature> arrayList1 = new ArrayList();
      byte b;
      for (b = 0; b < i; b++)
        arrayList.add(LMSPrivateKeyParameters.getInstance(paramObject)); 
      for (b = 0; b < i - 1; b++)
        arrayList1.add(LMSSignature.getInstance(paramObject)); 
      return new HSSPrivateKeyParameters(i, arrayList, arrayList1, l1, l2, bool);
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
  
  public int getL() {
    return this.l;
  }
  
  public synchronized long getIndex() {
    return this.index;
  }
  
  public synchronized LMSParameters[] getLMSParameters() {
    int i = this.keys.size();
    LMSParameters[] arrayOfLMSParameters = new LMSParameters[i];
    for (byte b = 0; b < i; b++) {
      LMSPrivateKeyParameters lMSPrivateKeyParameters = this.keys.get(b);
      arrayOfLMSParameters[b] = new LMSParameters(lMSPrivateKeyParameters.getSigParameters(), lMSPrivateKeyParameters.getOtsParameters());
    } 
    return arrayOfLMSParameters;
  }
  
  synchronized void incIndex() {
    this.index++;
  }
  
  private static HSSPrivateKeyParameters makeCopy(HSSPrivateKeyParameters paramHSSPrivateKeyParameters) {
    try {
      return getInstance(paramHSSPrivateKeyParameters.getEncoded());
    } catch (Exception exception) {
      throw new RuntimeException(exception.getMessage(), exception);
    } 
  }
  
  protected void updateHierarchy(LMSPrivateKeyParameters[] paramArrayOfLMSPrivateKeyParameters, LMSSignature[] paramArrayOfLMSSignature) {
    synchronized (this) {
      this.keys = Collections.unmodifiableList(Arrays.asList(paramArrayOfLMSPrivateKeyParameters));
      this.sig = Collections.unmodifiableList(Arrays.asList(paramArrayOfLMSSignature));
    } 
  }
  
  boolean isShard() {
    return this.isShard;
  }
  
  long getIndexLimit() {
    return this.indexLimit;
  }
  
  public long getUsagesRemaining() {
    return this.indexLimit - this.index;
  }
  
  LMSPrivateKeyParameters getRootKey() {
    return this.keys.get(0);
  }
  
  public HSSPrivateKeyParameters extractKeyShard(int paramInt) {
    synchronized (this) {
      if (getUsagesRemaining() < paramInt)
        throw new IllegalArgumentException("usageCount exceeds usages remaining in current leaf"); 
      long l1 = this.index + paramInt;
      long l2 = this.index;
      this.index += paramInt;
      ArrayList<LMSPrivateKeyParameters> arrayList = new ArrayList<LMSPrivateKeyParameters>(getKeys());
      ArrayList<LMSSignature> arrayList1 = new ArrayList<LMSSignature>(getSig());
      HSSPrivateKeyParameters hSSPrivateKeyParameters = makeCopy(new HSSPrivateKeyParameters(this.l, arrayList, arrayList1, l2, l1, true));
      resetKeyToIndex();
      return hSSPrivateKeyParameters;
    } 
  }
  
  synchronized List<LMSPrivateKeyParameters> getKeys() {
    return this.keys;
  }
  
  synchronized List<LMSSignature> getSig() {
    return this.sig;
  }
  
  void resetKeyToIndex() {
    List<LMSPrivateKeyParameters> list = getKeys();
    long[] arrayOfLong = new long[list.size()];
    long l = getIndex();
    int i;
    for (i = list.size() - 1; i >= 0; i--) {
      LMSigParameters lMSigParameters = ((LMSPrivateKeyParameters)list.get(i)).getSigParameters();
      int j = (1 << lMSigParameters.getH()) - 1;
      arrayOfLong[i] = l & j;
      l >>>= lMSigParameters.getH();
    } 
    i = 0;
    LMSPrivateKeyParameters[] arrayOfLMSPrivateKeyParameters = list.<LMSPrivateKeyParameters>toArray(new LMSPrivateKeyParameters[list.size()]);
    LMSSignature[] arrayOfLMSSignature = this.sig.<LMSSignature>toArray(new LMSSignature[this.sig.size()]);
    LMSPrivateKeyParameters lMSPrivateKeyParameters = getRootKey();
    if ((arrayOfLMSPrivateKeyParameters[0].getIndex() - 1) != arrayOfLong[0]) {
      arrayOfLMSPrivateKeyParameters[0] = LMS.generateKeys(lMSPrivateKeyParameters.getSigParameters(), lMSPrivateKeyParameters.getOtsParameters(), (int)arrayOfLong[0], lMSPrivateKeyParameters.getI(), lMSPrivateKeyParameters.getMasterSecret());
      i = 1;
    } 
    for (byte b = 1; b < arrayOfLong.length; b++) {
      LMSPrivateKeyParameters lMSPrivateKeyParameters1 = arrayOfLMSPrivateKeyParameters[b - 1];
      byte[] arrayOfByte1 = new byte[16];
      byte[] arrayOfByte2 = new byte[32];
      SeedDerive seedDerive = new SeedDerive(lMSPrivateKeyParameters1.getI(), lMSPrivateKeyParameters1.getMasterSecret(), DigestUtil.getDigest(lMSPrivateKeyParameters1.getOtsParameters().getDigestOID()));
      seedDerive.setQ((int)arrayOfLong[b - 1]);
      seedDerive.setJ(-2);
      seedDerive.deriveSeed(arrayOfByte2, true);
      byte[] arrayOfByte3 = new byte[32];
      seedDerive.deriveSeed(arrayOfByte3, false);
      System.arraycopy(arrayOfByte3, 0, arrayOfByte1, 0, arrayOfByte1.length);
      boolean bool1 = (b < arrayOfLong.length - 1) ? ((arrayOfLong[b] == (arrayOfLMSPrivateKeyParameters[b].getIndex() - 1)) ? true : false) : ((arrayOfLong[b] == arrayOfLMSPrivateKeyParameters[b].getIndex()) ? true : false);
      boolean bool2 = (Arrays.areEqual(arrayOfByte1, arrayOfLMSPrivateKeyParameters[b].getI()) && Arrays.areEqual(arrayOfByte2, arrayOfLMSPrivateKeyParameters[b].getMasterSecret())) ? true : false;
      if (!bool2) {
        arrayOfLMSPrivateKeyParameters[b] = LMS.generateKeys(((LMSPrivateKeyParameters)list.get(b)).getSigParameters(), ((LMSPrivateKeyParameters)list.get(b)).getOtsParameters(), (int)arrayOfLong[b], arrayOfByte1, arrayOfByte2);
        arrayOfLMSSignature[b - 1] = LMS.generateSign(arrayOfLMSPrivateKeyParameters[b - 1], arrayOfLMSPrivateKeyParameters[b].getPublicKey().toByteArray());
        i = 1;
      } else if (!bool1) {
        arrayOfLMSPrivateKeyParameters[b] = LMS.generateKeys(((LMSPrivateKeyParameters)list.get(b)).getSigParameters(), ((LMSPrivateKeyParameters)list.get(b)).getOtsParameters(), (int)arrayOfLong[b], arrayOfByte1, arrayOfByte2);
        i = 1;
      } 
    } 
    if (i != 0)
      updateHierarchy(arrayOfLMSPrivateKeyParameters, arrayOfLMSSignature); 
  }
  
  public synchronized HSSPublicKeyParameters getPublicKey() {
    return new HSSPublicKeyParameters(this.l, getRootKey().getPublicKey());
  }
  
  void replaceConsumedKey(int paramInt) {
    SeedDerive seedDerive = ((LMSPrivateKeyParameters)this.keys.get(paramInt - 1)).getCurrentOTSKey().getDerivationFunction();
    seedDerive.setJ(-2);
    byte[] arrayOfByte1 = new byte[32];
    seedDerive.deriveSeed(arrayOfByte1, true);
    byte[] arrayOfByte2 = new byte[32];
    seedDerive.deriveSeed(arrayOfByte2, false);
    byte[] arrayOfByte3 = new byte[16];
    System.arraycopy(arrayOfByte2, 0, arrayOfByte3, 0, arrayOfByte3.length);
    ArrayList<LMSPrivateKeyParameters> arrayList = new ArrayList<LMSPrivateKeyParameters>(this.keys);
    LMSPrivateKeyParameters lMSPrivateKeyParameters = this.keys.get(paramInt);
    arrayList.set(paramInt, LMS.generateKeys(lMSPrivateKeyParameters.getSigParameters(), lMSPrivateKeyParameters.getOtsParameters(), 0, arrayOfByte3, arrayOfByte1));
    ArrayList<LMSSignature> arrayList1 = new ArrayList<LMSSignature>(this.sig);
    arrayList1.set(paramInt - 1, LMS.generateSign(arrayList.get(paramInt - 1), ((LMSPrivateKeyParameters)arrayList.get(paramInt)).getPublicKey().toByteArray()));
    this.keys = Collections.unmodifiableList(arrayList);
    this.sig = Collections.unmodifiableList(arrayList1);
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject == null || getClass() != paramObject.getClass())
      return false; 
    HSSPrivateKeyParameters hSSPrivateKeyParameters = (HSSPrivateKeyParameters)paramObject;
    return (this.l != hSSPrivateKeyParameters.l) ? false : ((this.isShard != hSSPrivateKeyParameters.isShard) ? false : ((this.indexLimit != hSSPrivateKeyParameters.indexLimit) ? false : ((this.index != hSSPrivateKeyParameters.index) ? false : (!this.keys.equals(hSSPrivateKeyParameters.keys) ? false : this.sig.equals(hSSPrivateKeyParameters.sig)))));
  }
  
  public synchronized byte[] getEncoded() throws IOException {
    Composer composer = Composer.compose().u32str(0).u32str(this.l).u64str(this.index).u64str(this.indexLimit).bool(this.isShard);
    for (LMSPrivateKeyParameters lMSPrivateKeyParameters : this.keys)
      composer.bytes(lMSPrivateKeyParameters); 
    for (LMSSignature lMSSignature : this.sig)
      composer.bytes(lMSSignature); 
    return composer.build();
  }
  
  public int hashCode() {
    null = this.l;
    null = 31 * null + (this.isShard ? 1 : 0);
    null = 31 * null + this.keys.hashCode();
    null = 31 * null + this.sig.hashCode();
    null = 31 * null + (int)(this.indexLimit ^ this.indexLimit >>> 32L);
    return 31 * null + (int)(this.index ^ this.index >>> 32L);
  }
  
  protected Object clone() throws CloneNotSupportedException {
    return makeCopy(this);
  }
  
  public LMSContext generateLMSContext() {
    LMSSignedPubKey[] arrayOfLMSSignedPubKey;
    LMSPrivateKeyParameters lMSPrivateKeyParameters;
    int i = getL();
    synchronized (this) {
      HSS.rangeTestKeys(this);
      List<LMSPrivateKeyParameters> list = getKeys();
      List<LMSSignature> list1 = getSig();
      lMSPrivateKeyParameters = getKeys().get(i - 1);
      int j = 0;
      arrayOfLMSSignedPubKey = new LMSSignedPubKey[i - 1];
      while (j < i - 1) {
        arrayOfLMSSignedPubKey[j] = new LMSSignedPubKey(list1.get(j), ((LMSPrivateKeyParameters)list.get(j + 1)).getPublicKey());
        j++;
      } 
      incIndex();
    } 
    return lMSPrivateKeyParameters.generateLMSContext().withSignedPublicKeys(arrayOfLMSSignedPubKey);
  }
  
  public byte[] generateSignature(LMSContext paramLMSContext) {
    try {
      return HSS.generateSignature(getL(), paramLMSContext).getEncoded();
    } catch (IOException iOException) {
      throw new IllegalStateException("unable to encode signature: " + iOException.getMessage(), iOException);
    } 
  }
}
