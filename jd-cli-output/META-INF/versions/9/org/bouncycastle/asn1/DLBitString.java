package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;

public class DLBitString extends ASN1BitString {
  public DLBitString(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, 0);
  }
  
  public DLBitString(byte paramByte, int paramInt) {
    super(paramByte, paramInt);
  }
  
  public DLBitString(byte[] paramArrayOfbyte, int paramInt) {
    super(paramArrayOfbyte, paramInt);
  }
  
  public DLBitString(int paramInt) {
    super(getBytes(paramInt), getPadBits(paramInt));
  }
  
  public DLBitString(ASN1Encodable paramASN1Encodable) throws IOException {
    super(paramASN1Encodable.toASN1Primitive().getEncoded("DER"), 0);
  }
  
  DLBitString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    super(paramArrayOfbyte, paramBoolean);
  }
  
  boolean encodeConstructed() {
    return false;
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.contents.length);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 3, this.contents);
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
  
  static int encodedLength(boolean paramBoolean, int paramInt) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, paramInt);
  }
  
  static void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 3, paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  static void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean, byte paramByte, byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 3, paramByte, paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  static org.bouncycastle.asn1.DLBitString fromOctetString(ASN1OctetString paramASN1OctetString) {
    return new org.bouncycastle.asn1.DLBitString(paramASN1OctetString.getOctets(), true);
  }
}
