package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ApplicationSpecificParser;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.BERTaggedObjectParser;

public class BERApplicationSpecificParser extends BERTaggedObjectParser implements ASN1ApplicationSpecificParser {
  BERApplicationSpecificParser(int paramInt, ASN1StreamParser paramASN1StreamParser) {
    super(64, paramInt, paramASN1StreamParser);
  }
  
  public ASN1Encodable readObject() throws IOException {
    return parseExplicitBaseObject();
  }
}
