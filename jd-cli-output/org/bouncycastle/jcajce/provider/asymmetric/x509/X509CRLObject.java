package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.security.cert.CRLException;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;

class X509CRLObject extends X509CRLImpl {
  private final Object cacheLock = new Object();
  
  private X509CRLInternal internalCRLValue;
  
  private volatile boolean hashValueSet;
  
  private volatile int hashValue;
  
  X509CRLObject(JcaJceHelper paramJcaJceHelper, CertificateList paramCertificateList) throws CRLException {
    super(paramJcaJceHelper, paramCertificateList, createSigAlgName(paramCertificateList), createSigAlgParams(paramCertificateList), isIndirectCRL(paramCertificateList));
  }
  
  public byte[] getEncoded() throws CRLException {
    return Arrays.clone(getInternalCRL().getEncoded());
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (paramObject instanceof X509CRLObject) {
      X509CRLObject x509CRLObject = (X509CRLObject)paramObject;
      if (this.hashValueSet && x509CRLObject.hashValueSet) {
        if (this.hashValue != x509CRLObject.hashValue)
          return false; 
      } else if (null == this.internalCRLValue || null == x509CRLObject.internalCRLValue) {
        ASN1BitString aSN1BitString = this.c.getSignature();
        if (null != aSN1BitString && !aSN1BitString.equals(x509CRLObject.c.getSignature()))
          return false; 
      } 
      return getInternalCRL().equals(x509CRLObject.getInternalCRL());
    } 
    return getInternalCRL().equals(paramObject);
  }
  
  public int hashCode() {
    if (!this.hashValueSet) {
      this.hashValue = getInternalCRL().hashCode();
      this.hashValueSet = true;
    } 
    return this.hashValue;
  }
  
  private X509CRLInternal getInternalCRL() {
    synchronized (this.cacheLock) {
      if (null != this.internalCRLValue)
        return this.internalCRLValue; 
    } 
    byte[] arrayOfByte = null;
    X509CRLException x509CRLException = null;
    try {
      arrayOfByte = this.c.getEncoded("DER");
    } catch (IOException iOException) {
      x509CRLException = new X509CRLException(iOException);
    } 
    X509CRLInternal x509CRLInternal = new X509CRLInternal(this.bcHelper, this.c, this.sigAlgName, this.sigAlgParams, this.isIndirect, arrayOfByte, x509CRLException);
    synchronized (this.cacheLock) {
      if (null == this.internalCRLValue)
        this.internalCRLValue = x509CRLInternal; 
      return this.internalCRLValue;
    } 
  }
  
  private static String createSigAlgName(CertificateList paramCertificateList) throws CRLException {
    try {
      return X509SignatureUtil.getSignatureName(paramCertificateList.getSignatureAlgorithm());
    } catch (Exception exception) {
      throw new X509CRLException("CRL contents invalid: " + exception.getMessage(), exception);
    } 
  }
  
  private static byte[] createSigAlgParams(CertificateList paramCertificateList) throws CRLException {
    try {
      ASN1Encodable aSN1Encodable = paramCertificateList.getSignatureAlgorithm().getParameters();
      return (null == aSN1Encodable) ? null : aSN1Encodable.toASN1Primitive().getEncoded("DER");
    } catch (Exception exception) {
      throw new CRLException("CRL contents invalid: " + exception);
    } 
  }
  
  private static boolean isIndirectCRL(CertificateList paramCertificateList) throws CRLException {
    try {
      byte[] arrayOfByte = getExtensionOctets(paramCertificateList, Extension.issuingDistributionPoint.getId());
      return (null == arrayOfByte) ? false : IssuingDistributionPoint.getInstance(arrayOfByte).isIndirectCRL();
    } catch (Exception exception) {
      throw new ExtCRLException("Exception reading IssuingDistributionPoint", exception);
    } 
  }
  
  private static class X509CRLException extends CRLException {
    private final Throwable cause;
    
    X509CRLException(String param1String, Throwable param1Throwable) {
      super(param1String);
      this.cause = param1Throwable;
    }
    
    X509CRLException(Throwable param1Throwable) {
      this.cause = param1Throwable;
    }
    
    public Throwable getCause() {
      return this.cause;
    }
  }
}
