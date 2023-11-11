package org.bouncycastle.jcajce;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;

public interface PKIXCertRevocationChecker {
  void setParameter(String paramString, Object paramObject);
  
  void initialize(PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters) throws CertPathValidatorException;
  
  void check(Certificate paramCertificate) throws CertPathValidatorException;
}
