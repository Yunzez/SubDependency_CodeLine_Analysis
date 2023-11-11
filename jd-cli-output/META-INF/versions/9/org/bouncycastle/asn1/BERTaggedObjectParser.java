package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.BERApplicationSpecificParser;

public class BERTaggedObjectParser implements ASN1TaggedObjectParser {
  final int _tagClass;
  
  final int _tagNo;
  
  final ASN1StreamParser _parser;
  
  BERTaggedObjectParser(int paramInt1, int paramInt2, ASN1StreamParser paramASN1StreamParser) {
    this._tagClass = paramInt1;
    this._tagNo = paramInt2;
    this._parser = paramASN1StreamParser;
  }
  
  public int getTagClass() {
    return this._tagClass;
  }
  
  public int getTagNo() {
    return this._tagNo;
  }
  
  public boolean hasContextTag(int paramInt) {
    return (this._tagClass == 128 && this._tagNo == paramInt);
  }
  
  public boolean hasTag(int paramInt1, int paramInt2) {
    return (this._tagClass == paramInt1 && this._tagNo == paramInt2);
  }
  
  public boolean isConstructed() {
    return true;
  }
  
  public ASN1Encodable getObjectParser(int paramInt, boolean paramBoolean) throws IOException {
    if (128 != getTagClass())
      throw new ASN1Exception("this method only valid for CONTEXT_SPECIFIC tags"); 
    return parseBaseUniversal(paramBoolean, paramInt);
  }
  
  public ASN1Primitive getLoadedObject() throws IOException {
    return this._parser.loadTaggedIL(this._tagClass, this._tagNo);
  }
  
  public ASN1Encodable parseBaseUniversal(boolean paramBoolean, int paramInt) throws IOException {
    if (paramBoolean)
      return this._parser.parseObject(paramInt); 
    return this._parser.parseImplicitConstructedIL(paramInt);
  }
  
  public ASN1Encodable parseExplicitBaseObject() throws IOException {
    return this._parser.readObject();
  }
  
  public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
    return this._parser.parseTaggedObject();
  }
  
  public ASN1TaggedObjectParser parseImplicitBaseTagged(int paramInt1, int paramInt2) throws IOException {
    if (64 == paramInt1)
      return new BERApplicationSpecificParser(paramInt2, this._parser); 
    return new org.bouncycastle.asn1.BERTaggedObjectParser(paramInt1, paramInt2, this._parser);
  }
  
  public ASN1Primitive toASN1Primitive() {
    try {
      return getLoadedObject();
    } catch (IOException iOException) {
      throw new ASN1ParsingException(iOException.getMessage());
    } 
  }
}
