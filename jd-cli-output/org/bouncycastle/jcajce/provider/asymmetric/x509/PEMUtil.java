package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Base64;

class PEMUtil {
  private final Boundaries[] _supportedBoundaries;
  
  PEMUtil(String paramString) {
    this._supportedBoundaries = new Boundaries[] { new Boundaries(paramString), new Boundaries("X509 " + paramString), new Boundaries("PKCS7") };
  }
  
  private String readLine(InputStream paramInputStream) throws IOException {
    int i;
    StringBuffer stringBuffer = new StringBuffer();
    while (true) {
      if ((i = paramInputStream.read()) != 13 && i != 10 && i >= 0) {
        stringBuffer.append((char)i);
        continue;
      } 
      if (i < 0 || stringBuffer.length() != 0)
        break; 
    } 
    if (i < 0)
      return (stringBuffer.length() == 0) ? null : stringBuffer.toString(); 
    if (i == 13) {
      paramInputStream.mark(1);
      if ((i = paramInputStream.read()) == 10)
        paramInputStream.mark(1); 
      if (i > 0)
        paramInputStream.reset(); 
    } 
    return stringBuffer.toString();
  }
  
  private Boundaries getBoundaries(String paramString) {
    for (byte b = 0; b != this._supportedBoundaries.length; b++) {
      Boundaries boundaries = this._supportedBoundaries[b];
      if (boundaries.isTheExpectedHeader(paramString) || boundaries.isTheExpectedFooter(paramString))
        return boundaries; 
    } 
    return null;
  }
  
  ASN1Sequence readPEMObject(InputStream paramInputStream, boolean paramBoolean) throws IOException {
    StringBuffer stringBuffer = new StringBuffer();
    Boundaries boundaries1 = null;
    String str;
    while (boundaries1 == null && (str = readLine(paramInputStream)) != null) {
      boundaries1 = getBoundaries(str);
      if (boundaries1 != null && !boundaries1.isTheExpectedHeader(str))
        throw new IOException("malformed PEM data: found footer where header was expected"); 
    } 
    if (boundaries1 == null) {
      if (!paramBoolean)
        return null; 
      throw new IOException("malformed PEM data: no header found");
    } 
    Boundaries boundaries2 = null;
    while (boundaries2 == null && (str = readLine(paramInputStream)) != null) {
      boundaries2 = getBoundaries(str);
      if (boundaries2 != null) {
        if (!boundaries1.isTheExpectedFooter(str))
          throw new IOException("malformed PEM data: header/footer mismatch"); 
        continue;
      } 
      stringBuffer.append(str);
    } 
    if (boundaries2 == null)
      throw new IOException("malformed PEM data: no footer found"); 
    if (stringBuffer.length() != 0)
      try {
        return ASN1Sequence.getInstance(Base64.decode(stringBuffer.toString()));
      } catch (Exception exception) {
        throw new IOException("malformed PEM data encountered");
      }  
    return null;
  }
  
  private class Boundaries {
    private final String _header;
    
    private final String _footer;
    
    private Boundaries(String param1String) {
      this._header = "-----BEGIN " + param1String + "-----";
      this._footer = "-----END " + param1String + "-----";
    }
    
    public boolean isTheExpectedHeader(String param1String) {
      return param1String.startsWith(this._header);
    }
    
    public boolean isTheExpectedFooter(String param1String) {
      return param1String.startsWith(this._footer);
    }
  }
}
