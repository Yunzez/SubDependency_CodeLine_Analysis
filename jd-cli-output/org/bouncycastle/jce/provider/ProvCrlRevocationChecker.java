package org.bouncycastle.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class ProvCrlRevocationChecker implements PKIXCertRevocationChecker {
  private final JcaJceHelper helper;
  
  private PKIXCertRevocationCheckerParameters params;
  
  private Date currentDate = null;
  
  public ProvCrlRevocationChecker(JcaJceHelper paramJcaJceHelper) {
    this.helper = paramJcaJceHelper;
  }
  
  public void setParameter(String paramString, Object paramObject) {}
  
  public void initialize(PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters) {
    this.params = paramPKIXCertRevocationCheckerParameters;
    this.currentDate = new Date();
  }
  
  public void init(boolean paramBoolean) throws CertPathValidatorException {
    if (paramBoolean)
      throw new CertPathValidatorException("forward checking not supported"); 
    this.params = null;
    this.currentDate = new Date();
  }
  
  public void check(Certificate paramCertificate) throws CertPathValidatorException {
    try {
      RFC3280CertPathUtilities.checkCRLs(this.params, this.params.getParamsPKIX(), this.currentDate, this.params.getValidDate(), (X509Certificate)paramCertificate, this.params.getSigningCert(), this.params.getWorkingPublicKey(), this.params.getCertPath().getCertificates(), this.helper);
    } catch (AnnotatedException annotatedException) {
      Throwable throwable = annotatedException;
      if (null != annotatedException.getCause())
        throwable = annotatedException.getCause(); 
      throw new CertPathValidatorException(annotatedException.getMessage(), throwable, this.params.getCertPath(), this.params.getIndex());
    } 
  }
}
