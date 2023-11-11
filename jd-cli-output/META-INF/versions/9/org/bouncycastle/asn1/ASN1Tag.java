package META-INF.versions.9.org.bouncycastle.asn1;

final class ASN1Tag {
  private final int tagClass;
  
  private final int tagNumber;
  
  static org.bouncycastle.asn1.ASN1Tag create(int paramInt1, int paramInt2) {
    return new org.bouncycastle.asn1.ASN1Tag(paramInt1, paramInt2);
  }
  
  private ASN1Tag(int paramInt1, int paramInt2) {
    this.tagClass = paramInt1;
    this.tagNumber = paramInt2;
  }
  
  int getTagClass() {
    return this.tagClass;
  }
  
  int getTagNumber() {
    return this.tagNumber;
  }
}
