package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.SimpleTimeZone;
import java.util.TimeZone;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DateUtil;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

public class ASN1GeneralizedTime extends ASN1Primitive {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1GeneralizedTime.class, 24);
  
  final byte[] contents;
  
  public static org.bouncycastle.asn1.ASN1GeneralizedTime getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1GeneralizedTime)
      return (org.bouncycastle.asn1.ASN1GeneralizedTime)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1GeneralizedTime)
        return (org.bouncycastle.asn1.ASN1GeneralizedTime)aSN1Primitive; 
    } 
    if (paramObject instanceof byte[])
      try {
        return (org.bouncycastle.asn1.ASN1GeneralizedTime)TYPE.fromByteArray((byte[])paramObject);
      } catch (Exception exception) {
        throw new IllegalArgumentException("encoding error in getInstance: " + exception.toString());
      }  
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1GeneralizedTime getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1GeneralizedTime)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public ASN1GeneralizedTime(String paramString) {
    this.contents = Strings.toByteArray(paramString);
    try {
      getDate();
    } catch (ParseException parseException) {
      throw new IllegalArgumentException("invalid date string: " + parseException.getMessage());
    } 
  }
  
  public ASN1GeneralizedTime(Date paramDate) {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'", DateUtil.EN_Locale);
    simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
    this.contents = Strings.toByteArray(simpleDateFormat.format(paramDate));
  }
  
  public ASN1GeneralizedTime(Date paramDate, Locale paramLocale) {
    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'", paramLocale);
    simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
    this.contents = Strings.toByteArray(simpleDateFormat.format(paramDate));
  }
  
  ASN1GeneralizedTime(byte[] paramArrayOfbyte) {
    if (paramArrayOfbyte.length < 4)
      throw new IllegalArgumentException("GeneralizedTime string too short"); 
    this.contents = paramArrayOfbyte;
    if (!isDigit(0) || !isDigit(1) || !isDigit(2) || !isDigit(3))
      throw new IllegalArgumentException("illegal characters in GeneralizedTime string"); 
  }
  
  public String getTimeString() {
    return Strings.fromByteArray(this.contents);
  }
  
  public String getTime() {
    String str = Strings.fromByteArray(this.contents);
    if (str.charAt(str.length() - 1) == 'Z')
      return str.substring(0, str.length() - 1) + "GMT+00:00"; 
    int i = str.length() - 6;
    char c = str.charAt(i);
    if ((c == '-' || c == '+') && str.indexOf("GMT") == i - 3)
      return str; 
    i = str.length() - 5;
    c = str.charAt(i);
    if (c == '-' || c == '+')
      return str.substring(0, i) + "GMT" + str.substring(0, i) + ":" + str
        
        .substring(i, i + 3); 
    i = str.length() - 3;
    c = str.charAt(i);
    if (c == '-' || c == '+')
      return str.substring(0, i) + "GMT" + str.substring(0, i) + ":00"; 
    return str + str;
  }
  
  private String calculateGMTOffset(String paramString) {
    String str = "+";
    TimeZone timeZone = TimeZone.getDefault();
    int i = timeZone.getRawOffset();
    if (i < 0) {
      str = "-";
      i = -i;
    } 
    int j = i / 3600000;
    int k = (i - j * 60 * 60 * 1000) / 60000;
    try {
      if (timeZone.useDaylightTime()) {
        if (hasFractionalSeconds())
          paramString = pruneFractionalSeconds(paramString); 
        SimpleDateFormat simpleDateFormat = calculateGMTDateFormat();
        if (timeZone.inDaylightTime(simpleDateFormat
            .parse(paramString + "GMT" + paramString + str + ":" + convert(j))))
          j += str.equals("+") ? 1 : -1; 
      } 
    } catch (ParseException parseException) {}
    return "GMT" + str + convert(j) + ":" + convert(k);
  }
  
  private SimpleDateFormat calculateGMTDateFormat() {
    SimpleDateFormat simpleDateFormat;
    if (hasFractionalSeconds()) {
      simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSSz");
    } else if (hasSeconds()) {
      simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmssz");
    } else if (hasMinutes()) {
      simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmz");
    } else {
      simpleDateFormat = new SimpleDateFormat("yyyyMMddHHz");
    } 
    simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
    return simpleDateFormat;
  }
  
  private String pruneFractionalSeconds(String paramString) {
    String str = paramString.substring(14);
    byte b;
    for (b = 1; b < str.length(); b++) {
      char c = str.charAt(b);
      if ('0' > c || c > '9')
        break; 
    } 
    if (b - 1 > 3) {
      str = str.substring(0, 4) + str.substring(0, 4);
      paramString = paramString.substring(0, 14) + paramString.substring(0, 14);
    } else if (b - 1 == 1) {
      str = str.substring(0, b) + "00" + str.substring(0, b);
      paramString = paramString.substring(0, 14) + paramString.substring(0, 14);
    } else if (b - 1 == 2) {
      str = str.substring(0, b) + "0" + str.substring(0, b);
      paramString = paramString.substring(0, 14) + paramString.substring(0, 14);
    } 
    return paramString;
  }
  
  private String convert(int paramInt) {
    if (paramInt < 10)
      return "0" + paramInt; 
    return Integer.toString(paramInt);
  }
  
  public Date getDate() throws ParseException {
    SimpleDateFormat simpleDateFormat;
    String str1 = Strings.fromByteArray(this.contents);
    String str2 = str1;
    if (str1.endsWith("Z")) {
      if (hasFractionalSeconds()) {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");
      } else if (hasSeconds()) {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
      } else if (hasMinutes()) {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmm'Z'");
      } else {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHH'Z'");
      } 
      simpleDateFormat.setTimeZone(new SimpleTimeZone(0, "Z"));
    } else if (str1.indexOf('-') > 0 || str1.indexOf('+') > 0) {
      str2 = getTime();
      simpleDateFormat = calculateGMTDateFormat();
    } else {
      if (hasFractionalSeconds()) {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss.SSS");
      } else if (hasSeconds()) {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmmss");
      } else if (hasMinutes()) {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHHmm");
      } else {
        simpleDateFormat = new SimpleDateFormat("yyyyMMddHH");
      } 
      simpleDateFormat.setTimeZone(new SimpleTimeZone(0, TimeZone.getDefault().getID()));
    } 
    if (hasFractionalSeconds())
      str2 = pruneFractionalSeconds(str2); 
    return DateUtil.epochAdjust(simpleDateFormat.parse(str2));
  }
  
  protected boolean hasFractionalSeconds() {
    for (byte b = 0; b != this.contents.length; b++) {
      if (this.contents[b] == 46)
        if (b == 14)
          return true;  
    } 
    return false;
  }
  
  protected boolean hasSeconds() {
    return (isDigit(12) && isDigit(13));
  }
  
  protected boolean hasMinutes() {
    return (isDigit(10) && isDigit(11));
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
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 24, this.contents);
  }
  
  ASN1Primitive toDERObject() {
    return new DERGeneralizedTime(this.contents);
  }
  
  ASN1Primitive toDLObject() {
    return new DERGeneralizedTime(this.contents);
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1GeneralizedTime))
      return false; 
    return Arrays.areEqual(this.contents, ((org.bouncycastle.asn1.ASN1GeneralizedTime)paramASN1Primitive).contents);
  }
  
  public int hashCode() {
    return Arrays.hashCode(this.contents);
  }
  
  static org.bouncycastle.asn1.ASN1GeneralizedTime createPrimitive(byte[] paramArrayOfbyte) {
    return new org.bouncycastle.asn1.ASN1GeneralizedTime(paramArrayOfbyte);
  }
}
