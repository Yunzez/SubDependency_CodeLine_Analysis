package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ApplicationSpecific;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERFactory;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;

public class DERApplicationSpecific extends ASN1ApplicationSpecific {
  public DERApplicationSpecific(int paramInt, byte[] paramArrayOfbyte) {
    super(new DERTaggedObject(false, 64, paramInt, new DEROctetString(paramArrayOfbyte)));
  }
  
  public DERApplicationSpecific(int paramInt, ASN1Encodable paramASN1Encodable) throws IOException {
    this(true, paramInt, paramASN1Encodable);
  }
  
  public DERApplicationSpecific(boolean paramBoolean, int paramInt, ASN1Encodable paramASN1Encodable) throws IOException {
    super(new DERTaggedObject(paramBoolean, 64, paramInt, paramASN1Encodable));
  }
  
  public DERApplicationSpecific(int paramInt, ASN1EncodableVector paramASN1EncodableVector) {
    super(new DERTaggedObject(false, 64, paramInt, DERFactory.createSequence(paramASN1EncodableVector)));
  }
  
  DERApplicationSpecific(ASN1TaggedObject paramASN1TaggedObject) {
    super(paramASN1TaggedObject);
  }
  
  ASN1Primitive toDERObject() {
    return this;
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}