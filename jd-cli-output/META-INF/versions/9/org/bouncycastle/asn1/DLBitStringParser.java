package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1BitStringParser;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DLBitString;
import org.bouncycastle.asn1.DefiniteLengthInputStream;

public class DLBitStringParser implements ASN1BitStringParser {
  private final DefiniteLengthInputStream stream;
  
  private int padBits = 0;
  
  DLBitStringParser(DefiniteLengthInputStream paramDefiniteLengthInputStream) {
    this.stream = paramDefiniteLengthInputStream;
  }
  
  public InputStream getBitStream() throws IOException {
    return getBitStream(false);
  }
  
  public InputStream getOctetStream() throws IOException {
    return getBitStream(true);
  }
  
  public int getPadBits() {
    return this.padBits;
  }
  
  public ASN1Primitive getLoadedObject() throws IOException {
    return DLBitString.createPrimitive(this.stream.toByteArray());
  }
  
  public ASN1Primitive toASN1Primitive() {
    try {
      return getLoadedObject();
    } catch (IOException iOException) {
      throw new ASN1ParsingException("IOException converting stream to byte array: " + iOException.getMessage(), iOException);
    } 
  }
  
  private InputStream getBitStream(boolean paramBoolean) throws IOException {
    int i = this.stream.getRemaining();
    if (i < 1)
      throw new IllegalStateException("content octets cannot be empty"); 
    this.padBits = this.stream.read();
    if (this.padBits > 0) {
      if (i < 2)
        throw new IllegalStateException("zero length data with non-zero pad bits"); 
      if (this.padBits > 7)
        throw new IllegalStateException("pad bits cannot be greater than 7 or less than 0"); 
      if (paramBoolean)
        throw new IOException("expected octet-aligned bitstring, but found padBits: " + this.padBits); 
    } 
    return this.stream;
  }
}
