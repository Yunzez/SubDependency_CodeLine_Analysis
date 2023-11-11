package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSStoreableObjectInterface;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Pack;

public final class XMSSMTPublicKeyParameters extends XMSSMTKeyParameters implements XMSSStoreableObjectInterface, Encodable {
  private final XMSSMTParameters params;
  
  private final int oid;
  
  private final byte[] root;
  
  private final byte[] publicSeed;
  
  private XMSSMTPublicKeyParameters(Builder paramBuilder) {
    super(false, Builder.access$000(paramBuilder).getTreeDigest());
    this.params = Builder.access$000(paramBuilder);
    if (this.params == null)
      throw new NullPointerException("params == null"); 
    int i = this.params.getTreeDigestSize();
    byte[] arrayOfByte = Builder.access$100(paramBuilder);
    if (arrayOfByte != null) {
      byte b = 4;
      int j = i;
      int k = i;
      int m = 0;
      if (arrayOfByte.length == j + k) {
        this.oid = 0;
        this.root = XMSSUtil.extractBytesAtOffset(arrayOfByte, m, j);
        m += j;
        this.publicSeed = XMSSUtil.extractBytesAtOffset(arrayOfByte, m, k);
      } else if (arrayOfByte.length == b + j + k) {
        this.oid = Pack.bigEndianToInt(arrayOfByte, 0);
        m += b;
        this.root = XMSSUtil.extractBytesAtOffset(arrayOfByte, m, j);
        m += j;
        this.publicSeed = XMSSUtil.extractBytesAtOffset(arrayOfByte, m, k);
      } else {
        throw new IllegalArgumentException("public key has wrong size");
      } 
    } else {
      if (this.params.getOid() != null) {
        this.oid = this.params.getOid().getOid();
      } else {
        this.oid = 0;
      } 
      byte[] arrayOfByte1 = Builder.access$200(paramBuilder);
      if (arrayOfByte1 != null) {
        if (arrayOfByte1.length != i)
          throw new IllegalArgumentException("length of root must be equal to length of digest"); 
        this.root = arrayOfByte1;
      } else {
        this.root = new byte[i];
      } 
      byte[] arrayOfByte2 = Builder.access$300(paramBuilder);
      if (arrayOfByte2 != null) {
        if (arrayOfByte2.length != i)
          throw new IllegalArgumentException("length of publicSeed must be equal to length of digest"); 
        this.publicSeed = arrayOfByte2;
      } else {
        this.publicSeed = new byte[i];
      } 
    } 
  }
  
  public byte[] getEncoded() throws IOException {
    return toByteArray();
  }
  
  public byte[] toByteArray() {
    byte[] arrayOfByte;
    int i = this.params.getTreeDigestSize();
    byte b = 4;
    int j = i;
    int k = i;
    int m = 0;
    if (this.oid != 0) {
      arrayOfByte = new byte[b + j + k];
      Pack.intToBigEndian(this.oid, arrayOfByte, m);
      m += b;
    } else {
      arrayOfByte = new byte[j + k];
    } 
    XMSSUtil.copyBytesAtOffset(arrayOfByte, this.root, m);
    m += j;
    XMSSUtil.copyBytesAtOffset(arrayOfByte, this.publicSeed, m);
    return arrayOfByte;
  }
  
  public byte[] getRoot() {
    return XMSSUtil.cloneArray(this.root);
  }
  
  public byte[] getPublicSeed() {
    return XMSSUtil.cloneArray(this.publicSeed);
  }
  
  public XMSSMTParameters getParameters() {
    return this.params;
  }
}
