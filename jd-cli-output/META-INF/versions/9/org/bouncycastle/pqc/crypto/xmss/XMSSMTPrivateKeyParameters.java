package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import org.bouncycastle.pqc.crypto.xmss.BDSStateMap;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSStoreableObjectInterface;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;

public final class XMSSMTPrivateKeyParameters extends XMSSMTKeyParameters implements XMSSStoreableObjectInterface, Encodable {
  private final XMSSMTParameters params;
  
  private final byte[] secretKeySeed;
  
  private final byte[] secretKeyPRF;
  
  private final byte[] publicSeed;
  
  private final byte[] root;
  
  private volatile long index;
  
  private volatile BDSStateMap bdsState;
  
  private volatile boolean used;
  
  private XMSSMTPrivateKeyParameters(Builder paramBuilder) {
    super(true, Builder.access$000(paramBuilder).getTreeDigest());
    this.params = Builder.access$000(paramBuilder);
    if (this.params == null)
      throw new NullPointerException("params == null"); 
    int i = this.params.getTreeDigestSize();
    byte[] arrayOfByte = Builder.access$100(paramBuilder);
    if (arrayOfByte != null) {
      if (Builder.access$200(paramBuilder) == null)
        throw new NullPointerException("xmss == null"); 
      int j = this.params.getHeight();
      int k = (j + 7) / 8;
      int m = i;
      int n = i;
      int i1 = i;
      int i2 = i;
      int i3 = 0;
      this.index = XMSSUtil.bytesToXBigEndian(arrayOfByte, i3, k);
      if (!XMSSUtil.isIndexValid(j, this.index))
        throw new IllegalArgumentException("index out of bounds"); 
      i3 += k;
      this.secretKeySeed = XMSSUtil.extractBytesAtOffset(arrayOfByte, i3, m);
      i3 += m;
      this.secretKeyPRF = XMSSUtil.extractBytesAtOffset(arrayOfByte, i3, n);
      i3 += n;
      this.publicSeed = XMSSUtil.extractBytesAtOffset(arrayOfByte, i3, i1);
      i3 += i1;
      this.root = XMSSUtil.extractBytesAtOffset(arrayOfByte, i3, i2);
      i3 += i2;
      byte[] arrayOfByte1 = XMSSUtil.extractBytesAtOffset(arrayOfByte, i3, arrayOfByte.length - i3);
      try {
        BDSStateMap bDSStateMap = (BDSStateMap)XMSSUtil.deserialize(arrayOfByte1, BDSStateMap.class);
        this.bdsState = bDSStateMap.withWOTSDigest(Builder.access$200(paramBuilder).getTreeDigestOID());
      } catch (IOException iOException) {
        throw new IllegalArgumentException(iOException.getMessage(), iOException);
      } catch (ClassNotFoundException classNotFoundException) {
        throw new IllegalArgumentException(classNotFoundException.getMessage(), classNotFoundException);
      } 
    } else {
      this.index = Builder.access$300(paramBuilder);
      byte[] arrayOfByte1 = Builder.access$400(paramBuilder);
      if (arrayOfByte1 != null) {
        if (arrayOfByte1.length != i)
          throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest"); 
        this.secretKeySeed = arrayOfByte1;
      } else {
        this.secretKeySeed = new byte[i];
      } 
      byte[] arrayOfByte2 = Builder.access$500(paramBuilder);
      if (arrayOfByte2 != null) {
        if (arrayOfByte2.length != i)
          throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest"); 
        this.secretKeyPRF = arrayOfByte2;
      } else {
        this.secretKeyPRF = new byte[i];
      } 
      byte[] arrayOfByte3 = Builder.access$600(paramBuilder);
      if (arrayOfByte3 != null) {
        if (arrayOfByte3.length != i)
          throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest"); 
        this.publicSeed = arrayOfByte3;
      } else {
        this.publicSeed = new byte[i];
      } 
      byte[] arrayOfByte4 = Builder.access$700(paramBuilder);
      if (arrayOfByte4 != null) {
        if (arrayOfByte4.length != i)
          throw new IllegalArgumentException("size of root needs to be equal size of digest"); 
        this.root = arrayOfByte4;
      } else {
        this.root = new byte[i];
      } 
      BDSStateMap bDSStateMap = Builder.access$800(paramBuilder);
      if (bDSStateMap != null) {
        this.bdsState = bDSStateMap;
      } else {
        long l = Builder.access$300(paramBuilder);
        int j = this.params.getHeight();
        if (XMSSUtil.isIndexValid(j, l) && arrayOfByte3 != null && arrayOfByte1 != null) {
          this.bdsState = new BDSStateMap(this.params, Builder.access$300(paramBuilder), arrayOfByte3, arrayOfByte1);
        } else {
          this.bdsState = new BDSStateMap(Builder.access$900(paramBuilder) + 1L);
        } 
      } 
      if (Builder.access$900(paramBuilder) >= 0L && Builder.access$900(paramBuilder) != this.bdsState.getMaxIndex())
        throw new IllegalArgumentException("maxIndex set but not reflected in state"); 
    } 
  }
  
  public byte[] getEncoded() throws IOException {
    synchronized (this) {
      return toByteArray();
    } 
  }
  
  public byte[] toByteArray() {
    synchronized (this) {
      int i = this.params.getTreeDigestSize();
      int j = (this.params.getHeight() + 7) / 8;
      int k = i;
      int m = i;
      int n = i;
      int i1 = i;
      int i2 = j + k + m + n + i1;
      byte[] arrayOfByte1 = new byte[i2];
      int i3 = 0;
      byte[] arrayOfByte2 = XMSSUtil.toBytesBigEndian(this.index, j);
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, arrayOfByte2, i3);
      i3 += j;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.secretKeySeed, i3);
      i3 += k;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.secretKeyPRF, i3);
      i3 += m;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.publicSeed, i3);
      i3 += n;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.root, i3);
      try {
        return Arrays.concatenate(arrayOfByte1, XMSSUtil.serialize(this.bdsState));
      } catch (IOException iOException) {
        throw new IllegalStateException("error serializing bds state: " + iOException.getMessage(), iOException);
      } 
    } 
  }
  
  public long getIndex() {
    return this.index;
  }
  
  public long getUsagesRemaining() {
    synchronized (this) {
      return this.bdsState.getMaxIndex() - getIndex() + 1L;
    } 
  }
  
  public byte[] getSecretKeySeed() {
    return XMSSUtil.cloneArray(this.secretKeySeed);
  }
  
  public byte[] getSecretKeyPRF() {
    return XMSSUtil.cloneArray(this.secretKeyPRF);
  }
  
  public byte[] getPublicSeed() {
    return XMSSUtil.cloneArray(this.publicSeed);
  }
  
  public byte[] getRoot() {
    return XMSSUtil.cloneArray(this.root);
  }
  
  BDSStateMap getBDSState() {
    return this.bdsState;
  }
  
  public XMSSMTParameters getParameters() {
    return this.params;
  }
  
  public org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters getNextKey() {
    synchronized (this) {
      return extractKeyShard(1);
    } 
  }
  
  org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters rollKey() {
    synchronized (this) {
      if (getIndex() < this.bdsState.getMaxIndex()) {
        this.bdsState.updateState(this.params, this.index, this.publicSeed, this.secretKeySeed);
        this.index++;
        this.used = false;
      } else {
        this.index = this.bdsState.getMaxIndex() + 1L;
        this.bdsState = new BDSStateMap(this.bdsState.getMaxIndex());
        this.used = false;
      } 
      return this;
    } 
  }
  
  public org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters extractKeyShard(int paramInt) {
    if (paramInt < 1)
      throw new IllegalArgumentException("cannot ask for a shard with 0 keys"); 
    synchronized (this) {
      if (paramInt <= getUsagesRemaining()) {
        org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters xMSSMTPrivateKeyParameters = (new Builder(this.params)).withSecretKeySeed(this.secretKeySeed).withSecretKeyPRF(this.secretKeyPRF).withPublicSeed(this.publicSeed).withRoot(this.root).withIndex(getIndex()).withBDSState(new BDSStateMap(this.bdsState, getIndex() + paramInt - 1L)).build();
        for (int i = 0; i != paramInt; i++)
          rollKey(); 
        return xMSSMTPrivateKeyParameters;
      } 
      throw new IllegalArgumentException("usageCount exceeds usages remaining");
    } 
  }
}
