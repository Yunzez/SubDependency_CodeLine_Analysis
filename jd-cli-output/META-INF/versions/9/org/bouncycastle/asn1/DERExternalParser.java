package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1ExternalParser;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DLExternal;

public class DERExternalParser implements ASN1ExternalParser {
  private ASN1StreamParser _parser;
  
  public DERExternalParser(ASN1StreamParser paramASN1StreamParser) {
    this._parser = paramASN1StreamParser;
  }
  
  public ASN1Encodable readObject() throws IOException {
    return this._parser.readObject();
  }
  
  public ASN1Primitive getLoadedObject() throws IOException {
    return parse(this._parser);
  }
  
  public ASN1Primitive toASN1Primitive() {
    try {
      return getLoadedObject();
    } catch (IOException iOException) {
      throw new ASN1ParsingException("unable to get DER object", iOException);
    } catch (IllegalArgumentException illegalArgumentException) {
      throw new ASN1ParsingException("unable to get DER object", illegalArgumentException);
    } 
  }
  
  static DLExternal parse(ASN1StreamParser paramASN1StreamParser) throws IOException {
    try {
      return new DLExternal(paramASN1StreamParser.readVector());
    } catch (IllegalArgumentException illegalArgumentException) {
      throw new ASN1Exception(illegalArgumentException.getMessage(), illegalArgumentException);
    } 
  }
}
