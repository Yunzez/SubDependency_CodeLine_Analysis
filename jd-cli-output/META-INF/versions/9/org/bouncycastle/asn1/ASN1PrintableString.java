package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public abstract class ASN1PrintableString extends ASN1Primitive implements ASN1String {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1PrintableString.class, 19);
  
  final byte[] contents;
  
  public static org.bouncycastle.asn1.ASN1PrintableString getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1PrintableString)
      return (org.bouncycastle.asn1.ASN1PrintableString)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1PrintableString)
        return (org.bouncycastle.asn1.ASN1PrintableString)aSN1Primitive; 
    } 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.ASN1PrintableString)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1PrintableString getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1PrintableString)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  ASN1PrintableString(String paramString, boolean paramBoolean) {
    if (paramBoolean && !isPrintableString(paramString))
      throw new IllegalArgumentException("string contains illegal characters"); 
    this.contents = Strings.toByteArray(paramString);
  }
  
  ASN1PrintableString(byte[] paramArrayOfbyte, boolean paramBoolean) {
    this.contents = paramBoolean ? Arrays.clone(paramArrayOfbyte) : paramArrayOfbyte;
  }
  
  public final String getString() {
    return Strings.fromByteArray(this.contents);
  }
  
  public final byte[] getOctets() {
    return Arrays.clone(this.contents);
  }
  
  final boolean encodeConstructed() {
    return false;
  }
  
  final int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.contents.length);
  }
  
  final void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 19, this.contents);
  }
  
  final boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1PrintableString))
      return false; 
    org.bouncycastle.asn1.ASN1PrintableString aSN1PrintableString = (org.bouncycastle.asn1.ASN1PrintableString)paramASN1Primitive;
    return Arrays.areEqual(this.contents, aSN1PrintableString.contents);
  }
  
  public final int hashCode() {
    return Arrays.hashCode(this.contents);
  }
  
  public String toString() {
    return getString();
  }
  
  public static boolean isPrintableString(String paramString) {
    for (int i = paramString.length() - 1; i >= 0; i--) {
      char c = paramString.charAt(i);
      if (c > '')
        return false; 
      if ('a' > c || c > 'z')
        if ('A' > c || c > 'Z')
          if ('0' > c || c > '9')
            switch (c) {
              case ' ':
              case '\'':
              case '(':
              case ')':
              case '+':
              case ',':
              case '-':
              case '.':
              case '/':
              case ':':
              case '=':
              case '?':
                break;
              default:
                return false;
            }    
    } 
    return true;
  }
  
  static org.bouncycastle.asn1.ASN1PrintableString createPrimitive(byte[] paramArrayOfbyte) {
    return new DERPrintableString(paramArrayOfbyte, false);
  }
}
