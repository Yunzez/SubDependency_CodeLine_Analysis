package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.Encodable;

public abstract class ASN1Object implements ASN1Encodable, Encodable {
  public void encodeTo(OutputStream paramOutputStream) throws IOException {
    toASN1Primitive().encodeTo(paramOutputStream);
  }
  
  public void encodeTo(OutputStream paramOutputStream, String paramString) throws IOException {
    toASN1Primitive().encodeTo(paramOutputStream, paramString);
  }
  
  public byte[] getEncoded() throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    toASN1Primitive().encodeTo(byteArrayOutputStream);
    return byteArrayOutputStream.toByteArray();
  }
  
  public byte[] getEncoded(String paramString) throws IOException {
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    toASN1Primitive().encodeTo(byteArrayOutputStream, paramString);
    return byteArrayOutputStream.toByteArray();
  }
  
  public int hashCode() {
    return toASN1Primitive().hashCode();
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (!(paramObject instanceof ASN1Encodable))
      return false; 
    ASN1Encodable aSN1Encodable = (ASN1Encodable)paramObject;
    return toASN1Primitive().equals(aSN1Encodable.toASN1Primitive());
  }
  
  protected static boolean hasEncodedTagValue(Object paramObject, int paramInt) {
    return (paramObject instanceof byte[] && ((byte[])paramObject)[0] == paramInt);
  }
  
  public abstract ASN1Primitive toASN1Primitive();
}
