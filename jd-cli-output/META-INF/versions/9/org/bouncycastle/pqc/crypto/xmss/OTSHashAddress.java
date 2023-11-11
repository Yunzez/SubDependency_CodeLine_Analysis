package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import org.bouncycastle.pqc.crypto.xmss.XMSSAddress;
import org.bouncycastle.util.Pack;

final class OTSHashAddress extends XMSSAddress {
  private static final int TYPE = 0;
  
  private final int otsAddress;
  
  private final int chainAddress;
  
  private final int hashAddress;
  
  private OTSHashAddress(Builder paramBuilder) {
    super(paramBuilder);
    this.otsAddress = Builder.access$000(paramBuilder);
    this.chainAddress = Builder.access$100(paramBuilder);
    this.hashAddress = Builder.access$200(paramBuilder);
  }
  
  protected byte[] toByteArray() {
    byte[] arrayOfByte = super.toByteArray();
    Pack.intToBigEndian(this.otsAddress, arrayOfByte, 16);
    Pack.intToBigEndian(this.chainAddress, arrayOfByte, 20);
    Pack.intToBigEndian(this.hashAddress, arrayOfByte, 24);
    return arrayOfByte;
  }
  
  protected int getOTSAddress() {
    return this.otsAddress;
  }
  
  protected int getChainAddress() {
    return this.chainAddress;
  }
  
  protected int getHashAddress() {
    return this.hashAddress;
  }
}
