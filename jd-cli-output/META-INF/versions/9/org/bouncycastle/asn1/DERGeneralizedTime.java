package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.util.Date;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.util.Strings;

public class DERGeneralizedTime extends ASN1GeneralizedTime {
  public DERGeneralizedTime(byte[] paramArrayOfbyte) {
    super(paramArrayOfbyte);
  }
  
  public DERGeneralizedTime(Date paramDate) {
    super(paramDate);
  }
  
  public DERGeneralizedTime(String paramString) {
    super(paramString);
  }
  
  private byte[] getDERTime() {
    if (this.contents[this.contents.length - 1] == 90) {
      if (!hasMinutes()) {
        byte[] arrayOfByte = new byte[this.contents.length + 4];
        System.arraycopy(this.contents, 0, arrayOfByte, 0, this.contents.length - 1);
        System.arraycopy(Strings.toByteArray("0000Z"), 0, arrayOfByte, this.contents.length - 1, 5);
        return arrayOfByte;
      } 
      if (!hasSeconds()) {
        byte[] arrayOfByte = new byte[this.contents.length + 2];
        System.arraycopy(this.contents, 0, arrayOfByte, 0, this.contents.length - 1);
        System.arraycopy(Strings.toByteArray("00Z"), 0, arrayOfByte, this.contents.length - 1, 3);
        return arrayOfByte;
      } 
      if (hasFractionalSeconds()) {
        int i = this.contents.length - 2;
        while (i > 0 && this.contents[i] == 48)
          i--; 
        if (this.contents[i] == 46) {
          byte[] arrayOfByte1 = new byte[i + 1];
          System.arraycopy(this.contents, 0, arrayOfByte1, 0, i);
          arrayOfByte1[i] = 90;
          return arrayOfByte1;
        } 
        byte[] arrayOfByte = new byte[i + 2];
        System.arraycopy(this.contents, 0, arrayOfByte, 0, i + 1);
        arrayOfByte[i + 1] = 90;
        return arrayOfByte;
      } 
      return this.contents;
    } 
    return this.contents;
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, (getDERTime()).length);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 24, getDERTime());
  }
  
  ASN1Primitive toDERObject() {
    return this;
  }
  
  ASN1Primitive toDLObject() {
    return this;
  }
}
