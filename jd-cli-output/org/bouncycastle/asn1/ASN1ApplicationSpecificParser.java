package org.bouncycastle.asn1;

import java.io.IOException;

public interface ASN1ApplicationSpecificParser extends ASN1TaggedObjectParser {
  ASN1Encodable readObject() throws IOException;
}
