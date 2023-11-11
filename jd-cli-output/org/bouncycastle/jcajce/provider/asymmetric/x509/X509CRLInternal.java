package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.CRLException;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class X509CRLInternal extends X509CRLImpl {
  private final byte[] encoding;
  
  private final CRLException exception;
  
  X509CRLInternal(JcaJceHelper paramJcaJceHelper, CertificateList paramCertificateList, String paramString, byte[] paramArrayOfbyte1, boolean paramBoolean, byte[] paramArrayOfbyte2, CRLException paramCRLException) {
    super(paramJcaJceHelper, paramCertificateList, paramString, paramArrayOfbyte1, paramBoolean);
    this.encoding = paramArrayOfbyte2;
    this.exception = paramCRLException;
  }
  
  public byte[] getEncoded() throws CRLException {
    if (null != this.exception)
      throw this.exception; 
    if (null == this.encoding)
      throw new CRLException(); 
    return this.encoding;
  }
}
