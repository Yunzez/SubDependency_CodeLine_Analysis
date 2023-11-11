package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.util.Pack;

public abstract class XMSSAddress {
  private final int layerAddress;
  
  private final long treeAddress;
  
  private final int type;
  
  private final int keyAndMask;
  
  protected XMSSAddress(Builder paramBuilder) {
    this.layerAddress = Builder.access$000(paramBuilder);
    this.treeAddress = Builder.access$100(paramBuilder);
    this.type = Builder.access$200(paramBuilder);
    this.keyAndMask = Builder.access$300(paramBuilder);
  }
  
  protected byte[] toByteArray() {
    byte[] arrayOfByte = new byte[32];
    Pack.intToBigEndian(this.layerAddress, arrayOfByte, 0);
    Pack.longToBigEndian(this.treeAddress, arrayOfByte, 4);
    Pack.intToBigEndian(this.type, arrayOfByte, 12);
    Pack.intToBigEndian(this.keyAndMask, arrayOfByte, 28);
    return arrayOfByte;
  }
  
  protected final int getLayerAddress() {
    return this.layerAddress;
  }
  
  protected final long getTreeAddress() {
    return this.treeAddress;
  }
  
  public final int getType() {
    return this.type;
  }
  
  public final int getKeyAndMask() {
    return this.keyAndMask;
  }
}
