package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.security.cert.CertificateEncodingException;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class X509CertificateInternal extends X509CertificateImpl {
  private final byte[] encoding;
  
  private final CertificateEncodingException exception;
  
  X509CertificateInternal(JcaJceHelper paramJcaJceHelper, Certificate paramCertificate, BasicConstraints paramBasicConstraints, boolean[] paramArrayOfboolean, String paramString, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, CertificateEncodingException paramCertificateEncodingException) {
    super(paramJcaJceHelper, paramCertificate, paramBasicConstraints, paramArrayOfboolean, paramString, paramArrayOfbyte1);
    this.encoding = paramArrayOfbyte2;
    this.exception = paramCertificateEncodingException;
  }
  
  public byte[] getEncoded() throws CertificateEncodingException {
    if (null != this.exception)
      throw this.exception; 
    if (null == this.encoding)
      throw new CertificateEncodingException(); 
    return this.encoding;
  }
}
