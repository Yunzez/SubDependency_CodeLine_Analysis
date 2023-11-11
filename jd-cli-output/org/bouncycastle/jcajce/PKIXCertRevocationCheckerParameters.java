package org.bouncycastle.jcajce;

import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.util.Date;

public class PKIXCertRevocationCheckerParameters {
  private final PKIXExtendedParameters paramsPKIX;
  
  private final Date validDate;
  
  private final CertPath certPath;
  
  private final int index;
  
  private final X509Certificate signingCert;
  
  private final PublicKey workingPublicKey;
  
  public PKIXCertRevocationCheckerParameters(PKIXExtendedParameters paramPKIXExtendedParameters, Date paramDate, CertPath paramCertPath, int paramInt, X509Certificate paramX509Certificate, PublicKey paramPublicKey) {
    this.paramsPKIX = paramPKIXExtendedParameters;
    this.validDate = paramDate;
    this.certPath = paramCertPath;
    this.index = paramInt;
    this.signingCert = paramX509Certificate;
    this.workingPublicKey = paramPublicKey;
  }
  
  public PKIXExtendedParameters getParamsPKIX() {
    return this.paramsPKIX;
  }
  
  public Date getValidDate() {
    return new Date(this.validDate.getTime());
  }
  
  public CertPath getCertPath() {
    return this.certPath;
  }
  
  public int getIndex() {
    return this.index;
  }
  
  public X509Certificate getSigningCert() {
    return this.signingCert;
  }
  
  public PublicKey getWorkingPublicKey() {
    return this.workingPublicKey;
  }
}
