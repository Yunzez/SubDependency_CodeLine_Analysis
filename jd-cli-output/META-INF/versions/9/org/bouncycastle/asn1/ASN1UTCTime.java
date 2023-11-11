package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.DateUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class ASN1UTCTime extends ASN1Primitive {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1UTCTime.class, 23);
  
  final byte[] contents;
  
  public static org.bouncycastle.asn1.ASN1UTCTime getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1UTCTime)
      return (org.bouncycastle.asn1.ASN1UTCTime)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1UTCTime)
        return (org.bouncycastle.asn1.ASN1UTCTime)aSN1Primitive; 
    } 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.ASN1UTCTime)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1UTCTime getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1UTCTime)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public ASN1UTCTime(String paramString) {
    this.contents = Strings.toByteArray(paramString);
    try {
      getDate();
    } catch (ParseException parseException) {
      throw new IllegalArgumentException("invalid date string: " + parseException.getMessage());
    } 
  }
  
  public ASN1UTCTime(Date paramDate) {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyMMddHHmmss'Z'", DateUtil.EN_Locale);
    simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
    this.contents = Strings.toByteArray(simpleDateFormat.format(paramDate));
  }
  
  public ASN1UTCTime(Date paramDate, Locale paramLocale) {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyMMddHHmmss'Z'", paramLocale);
    simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
    this.contents = Strings.toByteArray(simpleDateFormat.format(paramDate));
  }
  
  ASN1UTCTime(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length < 2)
      throw new IllegalArgumentException("UTCTime string too short"); 
    this.contents = paramArrayOfbyte;
    if (!isDigit(0) || !isDigit(1))
      throw new IllegalArgumentException("illegal characters in UTCTime string"); 
  }
  
  public Date getDate() throws ParseException {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyMMddHHmmssz");
    return DateUtil.epochAdjust(simpleDateFormat.parse(getTime()));
  }
  
  public Date getAdjustedDate() throws ParseException {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmssz");
    simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
    return DateUtil.epochAdjust(simpleDateFormat.parse(getAdjustedTime()));
  }
  
  public String getTime() {
    String str1 = Strings.fromByteArray(this.contents);
    if (str1.indexOf('-') < 0 && str1.indexOf('+') < 0) {
      if (str1.length() == 11)
        return str1.substring(0, 10) + "00GMT+00:00"; 
      return str1.substring(0, 12) + "GMT+00:00";
    } 
    int i = str1.indexOf('-');
    if (i < 0)
      i = str1.indexOf('+'); 
    String str2 = str1;
    if (i == str1.length() - 3)
      str2 = str2 + "00"; 
    if (i == 10)
      return str2.substring(0, 10) + "00GMT" + str2.substring(0, 10) + ":" + str2.substring(10, 13); 
    return str2.substring(0, 12) + "GMT" + str2.substring(0, 12) + ":" + str2.substring(12, 15);
  }
  
  public String getAdjustedTime() {
    String str = getTime();
    return (str.charAt(0) < '5') ? ("20" + 
      
      str) : ("19" + 


      
      str);
  }
  
  private boolean isDigit(int paramInt) {
    return (this.contents.length > paramInt && this.contents[paramInt] >= 48 && this.contents[paramInt] <= 57);
  }
  
  final boolean encodeConstructed() {
    return false;
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, this.contents.length);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 23, this.contents);
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1UTCTime))
      return false; 
    return Arrays.areEqual(this.contents, ((org.bouncycastle.asn1.ASN1UTCTime)paramASN1Primitive).contents);
  }
  
  public int hashCode() {
    return Arrays.hashCode(this.contents);
  }
  
  public String toString() {
    return Strings.fromByteArray(this.contents);
  }
  
  static org.bouncycastle.asn1.ASN1UTCTime createPrimitive(byte[] paramArrayOfbyte) {
    return new org.bouncycastle.asn1.ASN1UTCTime(paramArrayOfbyte);
  }
}
