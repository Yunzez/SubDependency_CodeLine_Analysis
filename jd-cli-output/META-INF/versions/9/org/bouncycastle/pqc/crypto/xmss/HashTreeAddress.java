package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.pqc.crypto.xmss.XMSSAddress;
import org.bouncycastle.util.Pack;

final class HashTreeAddress extends XMSSAddress {
  private static final int TYPE = 2;
  
  private static final int PADDING = 0;
  
  private final int padding;
  
  private final int treeHeight;
  
  private final int treeIndex;
  
  private HashTreeAddress(Builder paramBuilder) {
    super(paramBuilder);
    this.padding = 0;
    this.treeHeight = Builder.access$000(paramBuilder);
    this.treeIndex = Builder.access$100(paramBuilder);
  }
  
  protected byte[] toByteArray() {
    byte[] arrayOfByte = super.toByteArray();
    Pack.intToBigEndian(this.padding, arrayOfByte, 16);
    Pack.intToBigEndian(this.treeHeight, arrayOfByte, 20);
    Pack.intToBigEndian(this.treeIndex, arrayOfByte, 24);
    return arrayOfByte;
  }
  
  protected int getPadding() {
    return this.padding;
  }
  
  protected int getTreeHeight() {
    return this.treeHeight;
  }
  
  protected int getTreeIndex() {
    return this.treeIndex;
  }
}
