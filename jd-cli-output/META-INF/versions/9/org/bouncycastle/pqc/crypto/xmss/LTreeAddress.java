package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.pqc.crypto.xmss.XMSSAddress;
import org.bouncycastle.util.Pack;

final class LTreeAddress extends XMSSAddress {
  private static final int TYPE = 1;
  
  private final int lTreeAddress;
  
  private final int treeHeight;
  
  private final int treeIndex;
  
  private LTreeAddress(Builder paramBuilder) {
    super(paramBuilder);
    this.lTreeAddress = Builder.access$000(paramBuilder);
    this.treeHeight = Builder.access$100(paramBuilder);
    this.treeIndex = Builder.access$200(paramBuilder);
  }
  
  protected byte[] toByteArray() {
    byte[] arrayOfByte = super.toByteArray();
    Pack.intToBigEndian(this.lTreeAddress, arrayOfByte, 16);
    Pack.intToBigEndian(this.treeHeight, arrayOfByte, 20);
    Pack.intToBigEndian(this.treeIndex, arrayOfByte, 24);
    return arrayOfByte;
  }
  
  protected int getLTreeAddress() {
    return this.lTreeAddress;
  }
  
  protected int getTreeHeight() {
    return this.treeHeight;
  }
  
  protected int getTreeIndex() {
    return this.treeIndex;
  }
}
