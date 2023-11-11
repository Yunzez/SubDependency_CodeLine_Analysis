package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.InMemoryRepresentable;

public interface ASN1TaggedObjectParser extends ASN1Encodable, InMemoryRepresentable {
  int getTagClass();
  
  int getTagNo();
  
  boolean hasContextTag(int paramInt);
  
  boolean hasTag(int paramInt1, int paramInt2);
  
  ASN1Encodable getObjectParser(int paramInt, boolean paramBoolean) throws IOException;
  
  ASN1Encodable parseBaseUniversal(boolean paramBoolean, int paramInt) throws IOException;
  
  ASN1Encodable parseExplicitBaseObject() throws IOException;
  
  org.bouncycastle.asn1.ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException;
  
  org.bouncycastle.asn1.ASN1TaggedObjectParser parseImplicitBaseTagged(int paramInt1, int paramInt2) throws IOException;
}
