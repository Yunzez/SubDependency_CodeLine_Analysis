package org.bouncycastle.asn1;

import java.io.IOException;

public class BERApplicationSpecificParser extends BERTaggedObjectParser implements ASN1ApplicationSpecificParser {
  BERApplicationSpecificParser(int paramInt, ASN1StreamParser paramASN1StreamParser) {
    super(64, paramInt, paramASN1StreamParser);
  }
  
  public ASN1Encodable readObject() throws IOException {
    return parseExplicitBaseObject();
  }
}
