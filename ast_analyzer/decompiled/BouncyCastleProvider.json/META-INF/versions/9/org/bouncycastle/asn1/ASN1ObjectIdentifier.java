package META-INF.versions.9.org.bouncycastle.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1RelativeOID;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1UniversalType;
import org.bouncycastle.asn1.OIDTokenizer;
import org.bouncycastle.util.Arrays;

public class ASN1ObjectIdentifier extends ASN1Primitive {
  static final ASN1UniversalType TYPE = (ASN1UniversalType)new Object(org.bouncycastle.asn1.ASN1ObjectIdentifier.class, 6);
  
  private static final long LONG_LIMIT = 72057594037927808L;
  
  public static org.bouncycastle.asn1.ASN1ObjectIdentifier fromContents(byte[] paramArrayOfbyte) {
    return createPrimitive(paramArrayOfbyte, true);
  }
  
  public static org.bouncycastle.asn1.ASN1ObjectIdentifier getInstance(Object paramObject) {
    if (paramObject == null || paramObject instanceof org.bouncycastle.asn1.ASN1ObjectIdentifier)
      return (org.bouncycastle.asn1.ASN1ObjectIdentifier)paramObject; 
    if (paramObject instanceof ASN1Encodable) {
      ASN1Primitive aSN1Primitive = ((ASN1Encodable)paramObject).toASN1Primitive();
      if (aSN1Primitive instanceof org.bouncycastle.asn1.ASN1ObjectIdentifier)
        return (org.bouncycastle.asn1.ASN1ObjectIdentifier)aSN1Primitive; 
    } else if (paramObject instanceof byte[]) {
      try {
        return (org.bouncycastle.asn1.ASN1ObjectIdentifier)TYPE.fromByteArray((byte[])paramObject);
      } catch (IOException iOException) {
        throw new IllegalArgumentException("failed to construct object identifier from byte[]: " + iOException.getMessage());
      } 
    } 
    throw new IllegalArgumentException("illegal object in getInstance: " + paramObject.getClass().getName());
  }
  
  public static org.bouncycastle.asn1.ASN1ObjectIdentifier getInstance(ASN1TaggedObject paramASN1TaggedObject, boolean paramBoolean) {
    if (!paramBoolean && !paramASN1TaggedObject.isParsed()) {
      ASN1Primitive aSN1Primitive = paramASN1TaggedObject.getObject();
      if (!(aSN1Primitive instanceof org.bouncycastle.asn1.ASN1ObjectIdentifier))
        return fromContents(ASN1OctetString.getInstance(aSN1Primitive).getOctets()); 
    } 
    return (org.bouncycastle.asn1.ASN1ObjectIdentifier)TYPE.getContextInstance(paramASN1TaggedObject, paramBoolean);
  }
  
  private static final ConcurrentMap<OidHandle, org.bouncycastle.asn1.ASN1ObjectIdentifier> pool = new ConcurrentHashMap<>();
  
  private final String identifier;
  
  private byte[] contents;
  
  ASN1ObjectIdentifier(byte[] paramArrayOfbyte, boolean paramBoolean) {
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
            if (l < 40L) {
              stringBuffer.append('0');
            } else if (l < 80L) {
              stringBuffer.append('1');
              l -= 40L;
            } else {
              stringBuffer.append('2');
              l -= 80L;
            } 
            bool = false;
          } 
          stringBuffer.append('.');
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
            stringBuffer.append('2');
            bigInteger = bigInteger.subtract(BigInteger.valueOf(80L));
            bool = false;
          } 
          stringBuffer.append('.');
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
  
  public ASN1ObjectIdentifier(String paramString) {
    if (paramString == null)
      throw new NullPointerException("'identifier' cannot be null"); 
    if (!isValidIdentifier(paramString))
      throw new IllegalArgumentException("string " + paramString + " not an OID"); 
    this.identifier = paramString;
  }
  
  ASN1ObjectIdentifier(org.bouncycastle.asn1.ASN1ObjectIdentifier paramASN1ObjectIdentifier, String paramString) {
    if (!ASN1RelativeOID.isValidIdentifier(paramString, 0))
      throw new IllegalArgumentException("string " + paramString + " not a valid OID branch"); 
    this.identifier = paramASN1ObjectIdentifier.getId() + "." + paramASN1ObjectIdentifier.getId();
  }
  
  public String getId() {
    return this.identifier;
  }
  
  public org.bouncycastle.asn1.ASN1ObjectIdentifier branch(String paramString) {
    return new org.bouncycastle.asn1.ASN1ObjectIdentifier(this, paramString);
  }
  
  public boolean on(org.bouncycastle.asn1.ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    String str1 = getId(), str2 = paramASN1ObjectIdentifier.getId();
    return (str1.length() > str2.length() && str1.charAt(str2.length()) == '.' && str1.startsWith(str2));
  }
  
  private void doOutput(ByteArrayOutputStream paramByteArrayOutputStream) {
    OIDTokenizer oIDTokenizer = new OIDTokenizer(this.identifier);
    int i = Integer.parseInt(oIDTokenizer.nextToken()) * 40;
    String str = oIDTokenizer.nextToken();
    if (str.length() <= 18) {
      ASN1RelativeOID.writeField(paramByteArrayOutputStream, i + Long.parseLong(str));
    } else {
      ASN1RelativeOID.writeField(paramByteArrayOutputStream, (new BigInteger(str)).add(BigInteger.valueOf(i)));
    } 
    while (oIDTokenizer.hasMoreTokens()) {
      String str1 = oIDTokenizer.nextToken();
      if (str1.length() <= 18) {
        ASN1RelativeOID.writeField(paramByteArrayOutputStream, Long.parseLong(str1));
        continue;
      } 
      ASN1RelativeOID.writeField(paramByteArrayOutputStream, new BigInteger(str1));
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
  
  boolean encodeConstructed() {
    return false;
  }
  
  int encodedLength(boolean paramBoolean) {
    return ASN1OutputStream.getLengthOfEncodingDL(paramBoolean, (getContents()).length);
  }
  
  void encode(ASN1OutputStream paramASN1OutputStream, boolean paramBoolean) throws IOException {
    paramASN1OutputStream.writeEncodingDL(paramBoolean, 6, getContents());
  }
  
  public int hashCode() {
    return this.identifier.hashCode();
  }
  
  boolean asn1Equals(ASN1Primitive paramASN1Primitive) {
    if (paramASN1Primitive == this)
      return true; 
    if (!(paramASN1Primitive instanceof org.bouncycastle.asn1.ASN1ObjectIdentifier))
      return false; 
    return this.identifier.equals(((org.bouncycastle.asn1.ASN1ObjectIdentifier)paramASN1Primitive).identifier);
  }
  
  public String toString() {
    return getId();
  }
  
  private static boolean isValidIdentifier(String paramString) {
    if (paramString.length() < 3 || paramString.charAt(1) != '.')
      return false; 
    char c = paramString.charAt(0);
    if (c < '0' || c > '2')
      return false; 
    return ASN1RelativeOID.isValidIdentifier(paramString, 2);
  }
  
  public org.bouncycastle.asn1.ASN1ObjectIdentifier intern() {
    OidHandle oidHandle = new OidHandle(getContents());
    org.bouncycastle.asn1.ASN1ObjectIdentifier aSN1ObjectIdentifier = pool.get(oidHandle);
    if (aSN1ObjectIdentifier == null) {
      aSN1ObjectIdentifier = pool.putIfAbsent(oidHandle, this);
      if (aSN1ObjectIdentifier == null)
        aSN1ObjectIdentifier = this; 
    } 
    return aSN1ObjectIdentifier;
  }
  
  static org.bouncycastle.asn1.ASN1ObjectIdentifier createPrimitive(byte[] paramArrayOfbyte, boolean paramBoolean) {
    OidHandle oidHandle = new OidHandle(paramArrayOfbyte);
    org.bouncycastle.asn1.ASN1ObjectIdentifier aSN1ObjectIdentifier = pool.get(oidHandle);
    if (aSN1ObjectIdentifier == null)
      return new org.bouncycastle.asn1.ASN1ObjectIdentifier(paramArrayOfbyte, paramBoolean); 
    return aSN1ObjectIdentifier;
  }
}
