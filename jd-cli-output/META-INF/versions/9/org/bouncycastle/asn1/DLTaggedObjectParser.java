package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERTaggedObjectParser;
import org.bouncycastle.asn1.DLApplicationSpecific;

class DLTaggedObjectParser extends BERTaggedObjectParser {
  private final boolean _constructed;
  
  DLTaggedObjectParser(int paramInt1, int paramInt2, boolean paramBoolean, ASN1StreamParser paramASN1StreamParser) {
    super(paramInt1, paramInt2, paramASN1StreamParser);
    this._constructed = paramBoolean;
  }
  
  public boolean isConstructed() {
    return this._constructed;
  }
  
  public ASN1Primitive getLoadedObject() throws IOException {
    return this._parser.loadTaggedDL(this._tagClass, this._tagNo, this._constructed);
  }
  
  public ASN1Encodable parseBaseUniversal(boolean paramBoolean, int paramInt) throws IOException {
    if (paramBoolean) {
      if (!this._constructed)
        throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)"); 
      return this._parser.parseObject(paramInt);
    } 
    return this._constructed ? 
      this._parser.parseImplicitConstructedDL(paramInt) : 
      this._parser.parseImplicitPrimitive(paramInt);
  }
  
  public ASN1Encodable parseExplicitBaseObject() throws IOException {
    if (!this._constructed)
      throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)"); 
    return this._parser.readObject();
  }
  
  public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
    if (!this._constructed)
      throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)"); 
    return this._parser.parseTaggedObject();
  }
  
  public ASN1TaggedObjectParser parseImplicitBaseTagged(int paramInt1, int paramInt2) throws IOException {
    if (64 == paramInt1)
      return (DLApplicationSpecific)this._parser.loadTaggedDL(paramInt1, paramInt2, this._constructed); 
    return new org.bouncycastle.asn1.DLTaggedObjectParser(paramInt1, paramInt2, this._constructed, this._parser);
  }
}
