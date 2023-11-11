package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1OctetStringParser;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DefiniteLengthInputStream;

public class DEROctetStringParser implements ASN1OctetStringParser {
  private DefiniteLengthInputStream stream;
  
  DEROctetStringParser(DefiniteLengthInputStream paramDefiniteLengthInputStream) {
    this.stream = paramDefiniteLengthInputStream;
  }
  
  public InputStream getOctetStream() {
    return this.stream;
  }
  
  public ASN1Primitive getLoadedObject() throws IOException {
    return new DEROctetString(this.stream.toByteArray());
  }
  
  public ASN1Primitive toASN1Primitive() {
    try {
      return getLoadedObject();
    } catch (IOException iOException) {
      throw new ASN1ParsingException("IOException converting stream to byte array: " + iOException.getMessage(), iOException);
    } 
  }
}
