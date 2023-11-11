package META-INF.versions.9.org.bouncycastle.asn1.x9;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.math.ec.ECFieldElement;

public class X9FieldElement extends ASN1Object {
  protected ECFieldElement f;
  
  private static X9IntegerConverter converter = new X9IntegerConverter();
  
  public X9FieldElement(ECFieldElement paramECFieldElement) {
    this.f = paramECFieldElement;
  }
  
  public ECFieldElement getValue() {
    return this.f;
  }
  
  public ASN1Primitive toASN1Primitive() {
    int i = converter.getByteLength(this.f);
    byte[] arrayOfByte = converter.integerToBytes(this.f.toBigInteger(), i);
    return new DEROctetString(arrayOfByte);
  }
}
