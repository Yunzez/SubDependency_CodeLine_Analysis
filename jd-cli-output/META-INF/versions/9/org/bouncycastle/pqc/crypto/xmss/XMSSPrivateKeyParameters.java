package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import org.bouncycastle.pqc.crypto.xmss.BDS;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;
import org.bouncycastle.pqc.crypto.xmss.XMSSKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSStoreableObjectInterface;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

public final class XMSSPrivateKeyParameters extends XMSSKeyParameters implements XMSSStoreableObjectInterface, Encodable {
  private final XMSSParameters params;
  
  private final byte[] secretKeySeed;
  
  private final byte[] secretKeyPRF;
  
  private final byte[] publicSeed;
  
  private final byte[] root;
  
  private volatile BDS bdsState;
  
  private XMSSPrivateKeyParameters(Builder paramBuilder) {
    super(true, Builder.access$000(paramBuilder).getTreeDigest());
    this.params = Builder.access$000(paramBuilder);
    if (this.params == null)
      throw new NullPointerException("params == null"); 
    int i = this.params.getTreeDigestSize();
    byte[] arrayOfByte = Builder.access$100(paramBuilder);
    if (arrayOfByte != null) {
      int j = this.params.getHeight();
      byte b = 4;
      int k = i;
      int m = i;
      int n = i;
      int i1 = i;
      int i2 = 0;
      int i3 = Pack.bigEndianToInt(arrayOfByte, i2);
      if (!XMSSUtil.isIndexValid(j, i3))
        throw new IllegalArgumentException("index out of bounds"); 
      i2 += b;
      this.secretKeySeed = XMSSUtil.extractBytesAtOffset(arrayOfByte, i2, k);
      i2 += k;
      this.secretKeyPRF = XMSSUtil.extractBytesAtOffset(arrayOfByte, i2, m);
      i2 += m;
      this.publicSeed = XMSSUtil.extractBytesAtOffset(arrayOfByte, i2, n);
      i2 += n;
      this.root = XMSSUtil.extractBytesAtOffset(arrayOfByte, i2, i1);
      i2 += i1;
      byte[] arrayOfByte1 = XMSSUtil.extractBytesAtOffset(arrayOfByte, i2, arrayOfByte.length - i2);
      try {
        BDS bDS = (BDS)XMSSUtil.deserialize(arrayOfByte1, BDS.class);
        if (bDS.getIndex() != i3)
          throw new IllegalStateException("serialized BDS has wrong index"); 
        this.bdsState = bDS.withWOTSDigest(Builder.access$000(paramBuilder).getTreeDigestOID());
      } catch (IOException iOException) {
        throw new IllegalArgumentException(iOException.getMessage(), iOException);
      } catch (ClassNotFoundException classNotFoundException) {
        throw new IllegalArgumentException(classNotFoundException.getMessage(), classNotFoundException);
      } 
    } else {
      byte[] arrayOfByte1 = Builder.access$200(paramBuilder);
      if (arrayOfByte1 != null) {
        if (arrayOfByte1.length != i)
          throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest"); 
        this.secretKeySeed = arrayOfByte1;
      } else {
        this.secretKeySeed = new byte[i];
      } 
      byte[] arrayOfByte2 = Builder.access$300(paramBuilder);
      if (arrayOfByte2 != null) {
        if (arrayOfByte2.length != i)
          throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest"); 
        this.secretKeyPRF = arrayOfByte2;
      } else {
        this.secretKeyPRF = new byte[i];
      } 
      byte[] arrayOfByte3 = Builder.access$400(paramBuilder);
      if (arrayOfByte3 != null) {
        if (arrayOfByte3.length != i)
          throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest"); 
        this.publicSeed = arrayOfByte3;
      } else {
        this.publicSeed = new byte[i];
      } 
      byte[] arrayOfByte4 = Builder.access$500(paramBuilder);
      if (arrayOfByte4 != null) {
        if (arrayOfByte4.length != i)
          throw new IllegalArgumentException("size of root needs to be equal size of digest"); 
        this.root = arrayOfByte4;
      } else {
        this.root = new byte[i];
      } 
      BDS bDS = Builder.access$600(paramBuilder);
      if (bDS != null) {
        this.bdsState = bDS;
      } else if (Builder.access$700(paramBuilder) < (1 << this.params.getHeight()) - 2 && arrayOfByte3 != null && arrayOfByte1 != null) {
        this.bdsState = new BDS(this.params, arrayOfByte3, arrayOfByte1, (OTSHashAddress)(new OTSHashAddress.Builder()).build(), Builder.access$700(paramBuilder));
      } else {
        this.bdsState = new BDS(this.params, (1 << this.params.getHeight()) - 1, Builder.access$700(paramBuilder));
      } 
      if (Builder.access$800(paramBuilder) >= 0 && Builder.access$800(paramBuilder) != this.bdsState.getMaxIndex())
        throw new IllegalArgumentException("maxIndex set but not reflected in state"); 
    } 
  }
  
  public long getUsagesRemaining() {
    synchronized (this) {
      return (this.bdsState.getMaxIndex() - getIndex() + 1);
    } 
  }
  
  public byte[] getEncoded() throws IOException {
    synchronized (this) {
      return toByteArray();
    } 
  }
  
  org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters rollKey() {
    synchronized (this) {
      if (this.bdsState.getIndex() < this.bdsState.getMaxIndex()) {
        this.bdsState = this.bdsState.getNextState(this.publicSeed, this.secretKeySeed, (OTSHashAddress)(new OTSHashAddress.Builder()).build());
      } else {
        this.bdsState = new BDS(this.params, this.bdsState.getMaxIndex(), this.bdsState.getMaxIndex() + 1);
      } 
      return this;
    } 
  }
  
  public org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters getNextKey() {
    synchronized (this) {
      return extractKeyShard(1);
    } 
  }
  
  public org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters extractKeyShard(int paramInt) {
    if (paramInt < 1)
      throw new IllegalArgumentException("cannot ask for a shard with 0 keys"); 
    synchronized (this) {
      if (paramInt <= getUsagesRemaining()) {
        org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters xMSSPrivateKeyParameters = (new Builder(this.params)).withSecretKeySeed(this.secretKeySeed).withSecretKeyPRF(this.secretKeyPRF).withPublicSeed(this.publicSeed).withRoot(this.root).withIndex(getIndex()).withBDSState(this.bdsState.withMaxIndex(this.bdsState.getIndex() + paramInt - 1, this.params.getTreeDigestOID())).build();
        if (paramInt == getUsagesRemaining()) {
          this.bdsState = new BDS(this.params, this.bdsState.getMaxIndex(), getIndex() + paramInt);
        } else {
          OTSHashAddress oTSHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).build();
          for (int i = 0; i != paramInt; i++)
            this.bdsState = this.bdsState.getNextState(this.publicSeed, this.secretKeySeed, oTSHashAddress); 
        } 
        return xMSSPrivateKeyParameters;
      } 
      throw new IllegalArgumentException("usageCount exceeds usages remaining");
    } 
  }
  
  public byte[] toByteArray() {
    synchronized (this) {
      int i = this.params.getTreeDigestSize();
      byte b = 4;
      int j = i;
      int k = i;
      int m = i;
      int n = i;
      int i1 = b + j + k + m + n;
      byte[] arrayOfByte1 = new byte[i1];
      int i2 = 0;
      Pack.intToBigEndian(this.bdsState.getIndex(), arrayOfByte1, i2);
      i2 += b;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.secretKeySeed, i2);
      i2 += j;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.secretKeyPRF, i2);
      i2 += k;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.publicSeed, i2);
      i2 += m;
      XMSSUtil.copyBytesAtOffset(arrayOfByte1, this.root, i2);
      byte[] arrayOfByte2 = null;
      try {
        arrayOfByte2 = XMSSUtil.serialize(this.bdsState);
      } catch (IOException iOException) {
        throw new RuntimeException("error serializing bds state: " + iOException.getMessage());
      } 
      return Arrays.concatenate(arrayOfByte1, arrayOfByte2);
    } 
  }
  
  public int getIndex() {
    return this.bdsState.getIndex();
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
  
  BDS getBDSState() {
    return this.bdsState;
  }
  
  public XMSSParameters getParameters() {
    return this.params;
  }
}
