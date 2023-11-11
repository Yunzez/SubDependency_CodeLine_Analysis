package org.bouncycastle.jce.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertPathBuilderSpi;
import java.security.cert.CertPathChecker;
import java.security.cert.CertPathParameters;
import java.security.cert.CertificateParsingException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathChecker;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jcajce.PKIXCertStore;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.x509.ExtendedPKIXBuilderParameters;

public class PKIXCertPathBuilderSpi_8 extends CertPathBuilderSpi {
  private final JcaJceHelper helper = new BCJcaJceHelper();
  
  private final boolean isForCRLCheck;
  
  private Exception certPathException;
  
  public PKIXCertPathBuilderSpi_8() {
    this(false);
  }
  
  PKIXCertPathBuilderSpi_8(boolean paramBoolean) {
    this.isForCRLCheck = paramBoolean;
  }
  
  public PKIXCertPathChecker engineGetRevocationChecker() {
    return new ProvRevocationChecker(this.helper);
  }
  
  public CertPathBuilderResult engineBuild(CertPathParameters paramCertPathParameters) throws CertPathBuilderException, InvalidAlgorithmParameterException {
    PKIXExtendedBuilderParameters pKIXExtendedBuilderParameters;
    if (paramCertPathParameters instanceof PKIXBuilderParameters) {
      PKIXExtendedBuilderParameters.Builder builder1;
      PKIXExtendedParameters.Builder builder = new PKIXExtendedParameters.Builder((PKIXBuilderParameters)paramCertPathParameters);
      if (paramCertPathParameters instanceof org.bouncycastle.x509.ExtendedPKIXParameters) {
        ExtendedPKIXBuilderParameters extendedPKIXBuilderParameters = (ExtendedPKIXBuilderParameters)paramCertPathParameters;
        Iterator<PKIXCertStore> iterator1 = extendedPKIXBuilderParameters.getAdditionalStores().iterator();
        while (iterator1.hasNext())
          builder.addCertificateStore(iterator1.next()); 
        builder1 = new PKIXExtendedBuilderParameters.Builder(builder.build());
        builder1.addExcludedCerts(extendedPKIXBuilderParameters.getExcludedCerts());
        builder1.setMaxPathLength(extendedPKIXBuilderParameters.getMaxPathLength());
      } else {
        builder1 = new PKIXExtendedBuilderParameters.Builder((PKIXBuilderParameters)paramCertPathParameters);
      } 
      pKIXExtendedBuilderParameters = builder1.build();
    } else if (paramCertPathParameters instanceof PKIXExtendedBuilderParameters) {
      pKIXExtendedBuilderParameters = (PKIXExtendedBuilderParameters)paramCertPathParameters;
    } else {
      throw new InvalidAlgorithmParameterException("Parameters must be an instance of " + PKIXBuilderParameters.class.getName() + " or " + PKIXExtendedBuilderParameters.class.getName() + ".");
    } 
    ArrayList arrayList = new ArrayList();
    Collection collection = CertPathValidatorUtilities.findTargets(pKIXExtendedBuilderParameters);
    CertPathBuilderResult certPathBuilderResult = null;
    Iterator<X509Certificate> iterator = collection.iterator();
    while (iterator.hasNext() && certPathBuilderResult == null) {
      X509Certificate x509Certificate = iterator.next();
      certPathBuilderResult = build(x509Certificate, pKIXExtendedBuilderParameters, arrayList);
    } 
    if (certPathBuilderResult == null && this.certPathException != null) {
      if (this.certPathException instanceof AnnotatedException)
        throw new CertPathBuilderException(this.certPathException.getMessage(), this.certPathException.getCause()); 
      throw new CertPathBuilderException("Possible certificate chain could not be validated.", this.certPathException);
    } 
    if (certPathBuilderResult == null && this.certPathException == null)
      throw new CertPathBuilderException("Unable to find certificate chain."); 
    return certPathBuilderResult;
  }
  
  protected CertPathBuilderResult build(X509Certificate paramX509Certificate, PKIXExtendedBuilderParameters paramPKIXExtendedBuilderParameters, List<X509Certificate> paramList) {
    if (paramList.contains(paramX509Certificate))
      return null; 
    if (paramPKIXExtendedBuilderParameters.getExcludedCerts().contains(paramX509Certificate))
      return null; 
    if (paramPKIXExtendedBuilderParameters.getMaxPathLength() != -1 && paramList.size() - 1 > paramPKIXExtendedBuilderParameters.getMaxPathLength())
      return null; 
    paramList.add(paramX509Certificate);
    CertPathBuilderResult certPathBuilderResult = null;
    try {
      CertificateFactory certificateFactory;
      PKIXCertPathValidatorSpi_8 pKIXCertPathValidatorSpi_8;
      try {
        certificateFactory = new CertificateFactory();
        pKIXCertPathValidatorSpi_8 = new PKIXCertPathValidatorSpi_8(this.isForCRLCheck);
      } catch (Exception exception) {
        throw new RuntimeException("Exception creating support classes.");
      } 
      if (CertPathValidatorUtilities.isIssuerTrustAnchor(paramX509Certificate, paramPKIXExtendedBuilderParameters.getBaseParameters().getTrustAnchors(), paramPKIXExtendedBuilderParameters.getBaseParameters().getSigProvider())) {
        CertPath certPath = null;
        PKIXCertPathValidatorResult pKIXCertPathValidatorResult = null;
        try {
          certPath = certificateFactory.engineGenerateCertPath(paramList);
        } catch (Exception exception) {
          throw new AnnotatedException("Certification path could not be constructed from certificate list.", exception);
        } 
        try {
          pKIXCertPathValidatorResult = (PKIXCertPathValidatorResult)pKIXCertPathValidatorSpi_8.engineValidate(certPath, paramPKIXExtendedBuilderParameters);
        } catch (Exception exception) {
          throw new AnnotatedException("Certification path could not be validated.", exception);
        } 
        return new PKIXCertPathBuilderResult(certPath, pKIXCertPathValidatorResult.getTrustAnchor(), pKIXCertPathValidatorResult.getPolicyTree(), pKIXCertPathValidatorResult.getPublicKey());
      } 
      ArrayList<PKIXCertStore> arrayList = new ArrayList();
      arrayList.addAll(paramPKIXExtendedBuilderParameters.getBaseParameters().getCertificateStores());
      try {
        arrayList.addAll(CertPathValidatorUtilities.getAdditionalStoresFromAltNames(paramX509Certificate.getExtensionValue(Extension.issuerAlternativeName.getId()), paramPKIXExtendedBuilderParameters.getBaseParameters().getNamedCertificateStoreMap()));
      } catch (CertificateParsingException certificateParsingException) {
        throw new AnnotatedException("No additional X.509 stores can be added from certificate locations.", certificateParsingException);
      } 
      HashSet hashSet = new HashSet();
      try {
        hashSet.addAll(CertPathValidatorUtilities.findIssuerCerts(paramX509Certificate, paramPKIXExtendedBuilderParameters.getBaseParameters().getCertStores(), arrayList));
      } catch (AnnotatedException annotatedException) {
        throw new AnnotatedException("Cannot find issuer certificate for certificate in certification path.", annotatedException);
      } 
      if (hashSet.isEmpty())
        throw new AnnotatedException("No issuer certificate for certificate in certification path found."); 
      Iterator<X509Certificate> iterator = hashSet.iterator();
      while (iterator.hasNext() && certPathBuilderResult == null) {
        X509Certificate x509Certificate = iterator.next();
        certPathBuilderResult = build(x509Certificate, paramPKIXExtendedBuilderParameters, paramList);
      } 
    } catch (AnnotatedException annotatedException) {
      this.certPathException = annotatedException;
    } 
    if (certPathBuilderResult == null)
      paramList.remove(paramX509Certificate); 
    return certPathBuilderResult;
  }
}
