package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERFactory;
import org.bouncycastle.asn1.BERTaggedObject;

public class BERApplicationSpecific extends ASN1ApplicationSpecific {
  public BERApplicationSpecific(int paramInt, ASN1Encodable paramASN1Encodable) throws IOException {
    this(true, paramInt, paramASN1Encodable);
  }
  
  public BERApplicationSpecific(boolean paramBoolean, int paramInt, ASN1Encodable paramASN1Encodable) throws IOException {
    super(new BERTaggedObject(paramBoolean, 64, paramInt, paramASN1Encodable));
  }
  
  public BERApplicationSpecific(int paramInt, ASN1EncodableVector paramASN1EncodableVector) {
    super(new BERTaggedObject(false, 64, paramInt, BERFactory.createSequence(paramASN1EncodableVector)));
  }
  
  BERApplicationSpecific(ASN1TaggedObject paramASN1TaggedObject) {
    super(paramASN1TaggedObject);
  }
}
