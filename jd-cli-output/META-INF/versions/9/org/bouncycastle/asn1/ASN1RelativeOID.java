package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.OIDTokenizer;
import org.bouncycastle.util.Arrays;

public class ASN1RelativeOID extends ASN1Primitive {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1RelativeOID.class, 13);
  
  private static final long LONG_LIMIT = 72057594037927808L;
  
  private final String identifier;
  
  private byte[] contents;
  
  public static org.bouncycastle.asn1.ASN1RelativeOID fromContents(byte[] paramArrayOfbyte) {
    return createPrimitive(paramArrayOfbyte, true);
  }
  
  public static org.bouncycastle.asn1.ASN1RelativeOID getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1RelativeOID)
      return (org.bouncycastle.asn1.ASN1RelativeOID)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1RelativeOID)
        return (org.bouncycastle.asn1.ASN1RelativeOID)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      byte[] arrayOfByte = (byte[])paramObject;
      try {
        return (org.bouncycastle.asn1.ASN1RelativeOID)TYPE.fromByteArray(arrayOfByte);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct relative OID from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1RelativeOID getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    return (org.bouncycastle.asn1.ASN1RelativeOID)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  public ASN1RelativeOID(String paramString) {
    if (paramString == null)
      throw new NullPointerException("'identifier' cannot be null"); 
    if (!isValidIdentifier(paramString, 0))
      throw new IllegalArgumentException("string " + paramString + " not a relative OID"); 
    this.identifier = paramString;
  }
  
  ASN1RelativeOID(org.bouncycastle.asn1.ASN1RelativeOID paramASN1RelativeOID, String paramString) {
    if (!isValidIdentifier(paramString, 0))
      throw new IllegalArgumentException("string " + paramString + " not a valid OID branch"); 
    this.identifier = paramASN1RelativeOID.getId() + "." + paramASN1RelativeOID.getId();
  }
  
  private ASN1RelativeOID(byte[] paramArrayOfbyte, boolean paramBoolean) {
    StringBuffer stringBuffer = new StringBuffer();
    long l = 0L;
    BigInteger bigInteger = null;
    boolean bool = true;
    for (byte b = 0; b != paramArrayOfbyte.length; b++) {
      int i = paramArrayOfbyte[b] & 0xFF;
      if (l <= 72057594037927808L) {
        l += (i & 0x7F);
        if ((i & 0x80) == 0) {
          if (bool) {
            bool = false;
          } else {
            stringBuffer.append('.');
          } 
          stringBuffer.append(l);
          l = 0L;
        } else {
          l <<= 7L;
        } 
      } else {
        if (bigInteger == null)
          bigInteger = BigInteger.valueOf(l); 
        bigInteger = bigInteger.or(BigInteger.valueOf((i & 0x7F)));
        if ((i & 0x80) == 0) {
          if (bool) {
            bool = false;
          } else {
            stringBuffer.append('.');
          } 
          stringBuffer.append(bigInteger);
          bigInteger = null;
          l = 0L;
        } else {
          bigInteger = bigInteger.shiftLeft(7);
        } 
      } 
    } 
    this.identifier = stringBuffer.toString();
    this.contents = paramBoolean ? Arrays.clone(paramArrayOfbyte) : paramArrayOfbyte;
  }
  
  public org.bouncycastle.asn1.ASN1RelativeOID branch(String paramString) {
    return new org.bouncycastle.asn1.ASN1RelativeOID(this, paramString);
  }
  
  public String getId() {
    return this.identifier;
  }
  
  public int hashCode() {
    return this.identifier.hashCode();
  }
  
  public String toString() {
    return getId();
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (this == paramASN1Primitive)
      return true; 
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1RelativeOID))
      return false; 
    org.bouncycastle.asn1.ASN1RelativeOID aSN1RelativeOID = (org.bouncycastle.asn1.ASN1RelativeOID)paramASN1Primitive;
    return this.identifier.equals(aSN1RelativeOID.identifier);
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, (getContents()).length);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 13, getContents());
  }
  
  boolean encodeConstructed() {
    return false;
  }
  
  private void doOutput(ByteArrayOutputStream paramByteArrayOutputStream) {
    OIDTokenizer oIDTokenizer = new OIDTokenizer(this.identifier);
    while (oIDTokenizer.hasMoreTokens()) {
      String str = oIDTokenizer.nextToken();
      if (str.length() <= 18) {
        writeField(paramByteArrayOutputStream, Long.parseLong(str));
        continue;
      } 
      writeField(paramByteArrayOutputStream, new BigInteger(str));
    } 
  }
  
  private synchronized byte[] getContents() {
    if (this.contents == null) {
      ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
      doOutput(byteArrayOutputStream);
      this.contents = byteArrayOutputStream.toByteArray();
    } 
    return this.contents;
  }
  
  static org.bouncycastle.asn1.ASN1RelativeOID createPrimitive(byte[] paramArrayOfbyte, boolean paramBoolean) {
    return new org.bouncycastle.asn1.ASN1RelativeOID(paramArrayOfbyte, paramBoolean);
  }
  
  static boolean isValidIdentifier(String paramString, int paramInt) {
    byte b = 0;
    int i = paramString.length();
    while (--i >= paramInt) {
      char c = paramString.charAt(i);
      if (c == '.') {
        if (0 == b || (b > 1 && paramString
          .charAt(i + 1) == '0'))
          return false; 
        b = 0;
        continue;
      } 
      if ('0' <= c && c <= '9') {
        b++;
        continue;
      } 
      return false;
    } 
    if (0 == b || (b > 1 && paramString
      .charAt(i + 1) == '0'))
      return false; 
    return true;
  }
  
  static void writeField(ByteArrayOutputStream paramByteArrayOutputStream, long paramLong) {
    byte[] arrayOfByte = new byte[9];
    byte b = 8;
    arrayOfByte[b] = (byte)((int)paramLong & 0x7F);
    while (paramLong >= 128L) {
      paramLong >>= 7L;
      arrayOfByte[--b] = (byte)((int)paramLong | 0x80);
    } 
    paramByteArrayOutputStream.write(arrayOfByte, b, 9 - b);
  }
  
  static void writeField(ByteArrayOutputStream paramByteArrayOutputStream, BigInteger paramBigInteger) {
    int i = (paramBigInteger.bitLength() + 6) / 7;
    if (i == 0) {
      paramByteArrayOutputStream.write(0);
    } else {
      BigInteger bigInteger = paramBigInteger;
      byte[] arrayOfByte = new byte[i];
      for (int j = i - 1; j >= 0; j--) {
        arrayOfByte[j] = (byte)(bigInteger.intValue() | 0x80);
        bigInteger = bigInteger.shiftRight(7);
      } 
      arrayOfByte[i - 1] = (byte)(arrayOfByte[i - 1] & Byte.MAX_VALUE);
      paramByteArrayOutputStream.write(arrayOfByte, 0, arrayOfByte.length);
    } 
  }
}
