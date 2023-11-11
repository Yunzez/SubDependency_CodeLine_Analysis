package META-INF.versions.9.org.bouncycastle.asn1;

import org.bouncycastle.asn1.ASN1Primitive;

public interface ASN1Encodable {
  ASN1Primitive toASN1Primitive();
}
