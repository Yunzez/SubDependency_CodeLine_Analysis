package org.bouncycastle.x509;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyNode;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.bouncycastle.asn1.x509.qualified.MonetaryValue;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.i18n.ErrorBundle;
import org.bouncycastle.i18n.LocaleString;
import org.bouncycastle.i18n.filter.TrustedInput;
import org.bouncycastle.i18n.filter.UntrustedInput;
import org.bouncycastle.i18n.filter.UntrustedUrlInput;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
import org.bouncycastle.jce.provider.PKIXPolicyNode;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Objects;

public class PKIXCertPathReviewer extends CertPathValidatorUtilities {
  private static final String QC_STATEMENT = Extension.qCStatements.getId();
  
  private static final String CRL_DIST_POINTS = Extension.cRLDistributionPoints.getId();
  
  private static final String AUTH_INFO_ACCESS = Extension.authorityInfoAccess.getId();
  
  private static final String RESOURCE_NAME = "org.bouncycastle.x509.CertPathReviewerMessages";
  
  protected CertPath certPath;
  
  protected PKIXParameters pkixParams;
  
  protected Date currentDate;
  
  protected Date validDate;
  
  protected List certs;
  
  protected int n;
  
  protected List[] notifications;
  
  protected List[] errors;
  
  protected TrustAnchor trustAnchor;
  
  protected PublicKey subjectPublicKey;
  
  protected PolicyNode policyTree;
  
  private boolean initialized;
  
  public void init(CertPath paramCertPath, PKIXParameters paramPKIXParameters) throws CertPathReviewerException {
    if (this.initialized)
      throw new IllegalStateException("object is already initialized!"); 
    this.initialized = true;
    if (paramCertPath == null)
      throw new NullPointerException("certPath was null"); 
    this.certPath = paramCertPath;
    this.certs = paramCertPath.getCertificates();
    this.n = this.certs.size();
    if (this.certs.isEmpty())
      throw new CertPathReviewerException(new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.emptyCertPath")); 
    this.pkixParams = (PKIXParameters)paramPKIXParameters.clone();
    this.currentDate = new Date();
    this.validDate = getValidityDate(this.pkixParams, this.currentDate);
    this.notifications = null;
    this.errors = null;
    this.trustAnchor = null;
    this.subjectPublicKey = null;
    this.policyTree = null;
  }
  
  public PKIXCertPathReviewer(CertPath paramCertPath, PKIXParameters paramPKIXParameters) throws CertPathReviewerException {
    init(paramCertPath, paramPKIXParameters);
  }
  
  public PKIXCertPathReviewer() {}
  
  public CertPath getCertPath() {
    return this.certPath;
  }
  
  public int getCertPathSize() {
    return this.n;
  }
  
  public List[] getErrors() {
    doChecks();
    return this.errors;
  }
  
  public List getErrors(int paramInt) {
    doChecks();
    return this.errors[paramInt + 1];
  }
  
  public List[] getNotifications() {
    doChecks();
    return this.notifications;
  }
  
  public List getNotifications(int paramInt) {
    doChecks();
    return this.notifications[paramInt + 1];
  }
  
  public PolicyNode getPolicyTree() {
    doChecks();
    return this.policyTree;
  }
  
  public PublicKey getSubjectPublicKey() {
    doChecks();
    return this.subjectPublicKey;
  }
  
  public TrustAnchor getTrustAnchor() {
    doChecks();
    return this.trustAnchor;
  }
  
  public boolean isValidCertPath() {
    doChecks();
    boolean bool = true;
    for (byte b = 0; b < this.errors.length; b++) {
      if (!this.errors[b].isEmpty()) {
        bool = false;
        break;
      } 
    } 
    return bool;
  }
  
  protected void addNotification(ErrorBundle paramErrorBundle) {
    this.notifications[0].add(paramErrorBundle);
  }
  
  protected void addNotification(ErrorBundle paramErrorBundle, int paramInt) {
    if (paramInt < -1 || paramInt >= this.n)
      throw new IndexOutOfBoundsException(); 
    this.notifications[paramInt + 1].add(paramErrorBundle);
  }
  
  protected void addError(ErrorBundle paramErrorBundle) {
    this.errors[0].add(paramErrorBundle);
  }
  
  protected void addError(ErrorBundle paramErrorBundle, int paramInt) {
    if (paramInt < -1 || paramInt >= this.n)
      throw new IndexOutOfBoundsException(); 
    this.errors[paramInt + 1].add(paramErrorBundle);
  }
  
  protected void doChecks() {
    if (!this.initialized)
      throw new IllegalStateException("Object not initialized. Call init() first."); 
    if (this.notifications == null) {
      this.notifications = new List[this.n + 1];
      this.errors = new List[this.n + 1];
      for (byte b = 0; b < this.notifications.length; b++) {
        this.notifications[b] = new ArrayList();
        this.errors[b] = new ArrayList();
      } 
      checkSignatures();
      checkNameConstraints();
      checkPathLength();
      checkPolicy();
      checkCriticalExtensions();
    } 
  }
  
  private void checkNameConstraints() {
    X509Certificate x509Certificate = null;
    PKIXNameConstraintValidator pKIXNameConstraintValidator = new PKIXNameConstraintValidator();
    try {
      for (int i = this.certs.size() - 1; i > 0; i--) {
        ASN1Sequence aSN1Sequence;
        int j = this.n - i;
        x509Certificate = this.certs.get(i);
        if (!isSelfIssued(x509Certificate)) {
          ASN1Sequence aSN1Sequence1;
          ASN1Sequence aSN1Sequence2;
          X500Principal x500Principal = getSubjectPrincipal(x509Certificate);
          ASN1InputStream aSN1InputStream = new ASN1InputStream(new ByteArrayInputStream(x500Principal.getEncoded()));
          try {
            aSN1Sequence1 = (ASN1Sequence)aSN1InputStream.readObject();
          } catch (IOException iOException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.ncSubjectNameError", new Object[] { new UntrustedInput(x500Principal) });
            throw new CertPathReviewerException(errorBundle, iOException, this.certPath, i);
          } 
          try {
            pKIXNameConstraintValidator.checkPermittedDN(aSN1Sequence1);
          } catch (PKIXNameConstraintValidatorException pKIXNameConstraintValidatorException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.notPermittedDN", new Object[] { new UntrustedInput(x500Principal.getName()) });
            throw new CertPathReviewerException(errorBundle, pKIXNameConstraintValidatorException, this.certPath, i);
          } 
          try {
            pKIXNameConstraintValidator.checkExcludedDN(aSN1Sequence1);
          } catch (PKIXNameConstraintValidatorException pKIXNameConstraintValidatorException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.excludedDN", new Object[] { new UntrustedInput(x500Principal.getName()) });
            throw new CertPathReviewerException(errorBundle, pKIXNameConstraintValidatorException, this.certPath, i);
          } 
          try {
            aSN1Sequence2 = (ASN1Sequence)getExtensionValue(x509Certificate, SUBJECT_ALTERNATIVE_NAME);
          } catch (AnnotatedException annotatedException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.subjAltNameExtError");
            throw new CertPathReviewerException(errorBundle, annotatedException, this.certPath, i);
          } 
          if (aSN1Sequence2 != null)
            for (byte b = 0; b < aSN1Sequence2.size(); b++) {
              GeneralName generalName = GeneralName.getInstance(aSN1Sequence2.getObjectAt(b));
              try {
                pKIXNameConstraintValidator.checkPermitted(generalName);
                pKIXNameConstraintValidator.checkExcluded(generalName);
              } catch (PKIXNameConstraintValidatorException pKIXNameConstraintValidatorException) {
                ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.notPermittedEmail", new Object[] { new UntrustedInput(generalName) });
                throw new CertPathReviewerException(errorBundle, pKIXNameConstraintValidatorException, this.certPath, i);
              } 
            }  
        } 
        try {
          aSN1Sequence = (ASN1Sequence)getExtensionValue(x509Certificate, NAME_CONSTRAINTS);
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.ncExtError");
          throw new CertPathReviewerException(errorBundle, annotatedException, this.certPath, i);
        } 
        if (aSN1Sequence != null) {
          NameConstraints nameConstraints = NameConstraints.getInstance(aSN1Sequence);
          GeneralSubtree[] arrayOfGeneralSubtree1 = nameConstraints.getPermittedSubtrees();
          if (arrayOfGeneralSubtree1 != null)
            pKIXNameConstraintValidator.intersectPermittedSubtree(arrayOfGeneralSubtree1); 
          GeneralSubtree[] arrayOfGeneralSubtree2 = nameConstraints.getExcludedSubtrees();
          if (arrayOfGeneralSubtree2 != null)
            for (byte b = 0; b != arrayOfGeneralSubtree2.length; b++)
              pKIXNameConstraintValidator.addExcludedSubtree(arrayOfGeneralSubtree2[b]);  
        } 
      } 
    } catch (CertPathReviewerException certPathReviewerException) {
      addError(certPathReviewerException.getErrorMessage(), certPathReviewerException.getIndex());
    } 
  }
  
  private void checkPathLength() {
    int i = this.n;
    byte b = 0;
    X509Certificate x509Certificate = null;
    for (int j = this.certs.size() - 1; j > 0; j--) {
      BasicConstraints basicConstraints;
      int k = this.n - j;
      x509Certificate = this.certs.get(j);
      if (!isSelfIssued(x509Certificate)) {
        if (i <= 0) {
          basicConstraints = (BasicConstraints)new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.pathLengthExtended");
          addError((ErrorBundle)basicConstraints);
        } 
        i--;
        b++;
      } 
      try {
        basicConstraints = BasicConstraints.getInstance(getExtensionValue(x509Certificate, BASIC_CONSTRAINTS));
      } catch (AnnotatedException annotatedException) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.processLengthConstError");
        addError(errorBundle1, j);
        basicConstraints = null;
      } 
      if (basicConstraints != null) {
        BigInteger bigInteger = basicConstraints.getPathLenConstraint();
        if (bigInteger != null) {
          int m = bigInteger.intValue();
          if (m < i)
            i = m; 
        } 
      } 
    } 
    ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.totalPathLength", new Object[] { Integers.valueOf(b) });
    addNotification(errorBundle);
  }
  
  private void checkSignatures() {
    PublicKey publicKey;
    TrustAnchor trustAnchor = null;
    X500Principal x500Principal1 = null;
    ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.certPathValidDate", new Object[] { new TrustedInput(this.validDate), new TrustedInput(this.currentDate) });
    addNotification(errorBundle);
    try {
      X509Certificate x509Certificate = this.certs.get(this.certs.size() - 1);
      Collection<TrustAnchor> collection = getTrustAnchors(x509Certificate, this.pkixParams.getTrustAnchors());
      if (collection.size() > 1) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.conflictingTrustAnchors", new Object[] { Integers.valueOf(collection.size()), new UntrustedInput(x509Certificate.getIssuerX500Principal()) });
        addError(errorBundle1);
      } else if (collection.isEmpty()) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noTrustAnchorFound", new Object[] { new UntrustedInput(x509Certificate.getIssuerX500Principal()), Integers.valueOf(this.pkixParams.getTrustAnchors().size()) });
        addError(errorBundle1);
      } else {
        PublicKey publicKey1;
        trustAnchor = collection.iterator().next();
        if (trustAnchor.getTrustedCert() != null) {
          publicKey1 = trustAnchor.getTrustedCert().getPublicKey();
        } else {
          publicKey1 = trustAnchor.getCAPublicKey();
        } 
        try {
          CertPathValidatorUtilities.verifyX509Certificate(x509Certificate, publicKey1, this.pkixParams.getSigProvider());
        } catch (SignatureException signatureException) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.trustButInvalidCert");
          addError(errorBundle1);
        } catch (Exception exception) {}
      } 
    } catch (CertPathReviewerException certPathReviewerException) {
      addError(certPathReviewerException.getErrorMessage());
    } catch (Throwable throwable) {
      ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.unknown", new Object[] { new UntrustedInput(throwable.getMessage()), new UntrustedInput(throwable) });
      addError(errorBundle1);
    } 
    if (trustAnchor != null) {
      X509Certificate x509Certificate = trustAnchor.getTrustedCert();
      try {
        if (x509Certificate != null) {
          x500Principal1 = getSubjectPrincipal(x509Certificate);
        } else {
          x500Principal1 = new X500Principal(trustAnchor.getCAName());
        } 
      } catch (IllegalArgumentException illegalArgumentException) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.trustDNInvalid", new Object[] { new UntrustedInput(trustAnchor.getCAName()) });
        addError(errorBundle1);
      } 
      if (x509Certificate != null) {
        boolean[] arrayOfBoolean = x509Certificate.getKeyUsage();
        if (arrayOfBoolean != null && (arrayOfBoolean.length <= 5 || !arrayOfBoolean[5])) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.trustKeyUsage");
          addNotification(errorBundle1);
        } 
      } 
    } 
    errorBundle = null;
    X500Principal x500Principal2 = x500Principal1;
    X509Certificate x509Certificate1 = null;
    AlgorithmIdentifier algorithmIdentifier = null;
    ASN1ObjectIdentifier aSN1ObjectIdentifier = null;
    ASN1Encodable aSN1Encodable = null;
    if (trustAnchor != null) {
      x509Certificate1 = trustAnchor.getTrustedCert();
      if (x509Certificate1 != null) {
        publicKey = x509Certificate1.getPublicKey();
      } else {
        publicKey = trustAnchor.getCAPublicKey();
      } 
      try {
        algorithmIdentifier = getAlgorithmIdentifier(publicKey);
        aSN1ObjectIdentifier = algorithmIdentifier.getAlgorithm();
        aSN1Encodable = algorithmIdentifier.getParameters();
      } catch (CertPathValidatorException certPathValidatorException) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.trustPubKeyError");
        addError(errorBundle1);
        algorithmIdentifier = null;
      } 
    } 
    X509Certificate x509Certificate2 = null;
    for (int i = this.certs.size() - 1; i >= 0; i--) {
      int j = this.n - i;
      x509Certificate2 = this.certs.get(i);
      if (publicKey != null) {
        try {
          CertPathValidatorUtilities.verifyX509Certificate(x509Certificate2, publicKey, this.pkixParams.getSigProvider());
        } catch (GeneralSecurityException generalSecurityException) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.signatureNotVerified", new Object[] { generalSecurityException.getMessage(), generalSecurityException, generalSecurityException.getClass().getName() });
          addError(errorBundle1, i);
        } 
      } else if (isSelfIssued(x509Certificate2)) {
        try {
          CertPathValidatorUtilities.verifyX509Certificate(x509Certificate2, x509Certificate2.getPublicKey(), this.pkixParams.getSigProvider());
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.rootKeyIsValidButNotATrustAnchor");
          addError(errorBundle1, i);
        } catch (GeneralSecurityException generalSecurityException) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.signatureNotVerified", new Object[] { generalSecurityException.getMessage(), generalSecurityException, generalSecurityException.getClass().getName() });
          addError(errorBundle1, i);
        } 
      } else {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.NoIssuerPublicKey");
        byte[] arrayOfByte = x509Certificate2.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (arrayOfByte != null) {
          AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(DEROctetString.getInstance(arrayOfByte).getOctets());
          GeneralNames generalNames = authorityKeyIdentifier.getAuthorityCertIssuer();
          if (generalNames != null) {
            GeneralName generalName = generalNames.getNames()[0];
            BigInteger bigInteger = authorityKeyIdentifier.getAuthorityCertSerialNumber();
            if (bigInteger != null) {
              Object[] arrayOfObject = { new LocaleString("org.bouncycastle.x509.CertPathReviewerMessages", "missingIssuer"), " \"", generalName, "\" ", new LocaleString("org.bouncycastle.x509.CertPathReviewerMessages", "missingSerial"), " ", bigInteger };
              errorBundle1.setExtraArguments(arrayOfObject);
            } 
          } 
        } 
        addError(errorBundle1, i);
      } 
      try {
        x509Certificate2.checkValidity(this.validDate);
      } catch (CertificateNotYetValidException certificateNotYetValidException) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.certificateNotYetValid", new Object[] { new TrustedInput(x509Certificate2.getNotBefore()) });
        addError(errorBundle1, i);
      } catch (CertificateExpiredException certificateExpiredException) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.certificateExpired", new Object[] { new TrustedInput(x509Certificate2.getNotAfter()) });
        addError(errorBundle1, i);
      } 
      if (this.pkixParams.isRevocationEnabled()) {
        CRLDistPoint cRLDistPoint = null;
        try {
          ASN1Primitive aSN1Primitive = getExtensionValue(x509Certificate2, CRL_DIST_POINTS);
          if (aSN1Primitive != null)
            cRLDistPoint = CRLDistPoint.getInstance(aSN1Primitive); 
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlDistPtExtError");
          addError(errorBundle1, i);
        } 
        AuthorityInformationAccess authorityInformationAccess = null;
        try {
          ASN1Primitive aSN1Primitive = getExtensionValue(x509Certificate2, AUTH_INFO_ACCESS);
          if (aSN1Primitive != null)
            authorityInformationAccess = AuthorityInformationAccess.getInstance(aSN1Primitive); 
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlAuthInfoAccError");
          addError(errorBundle1, i);
        } 
        Vector vector1 = getCRLDistUrls(cRLDistPoint);
        Vector vector2 = getOCSPUrls(authorityInformationAccess);
        Iterator iterator = vector1.iterator();
        while (iterator.hasNext()) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlDistPoint", new Object[] { new UntrustedUrlInput(iterator.next()) });
          addNotification(errorBundle1, i);
        } 
        iterator = vector2.iterator();
        while (iterator.hasNext()) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.ocspLocation", new Object[] { new UntrustedUrlInput(iterator.next()) });
          addNotification(errorBundle1, i);
        } 
        try {
          checkRevocation(this.pkixParams, x509Certificate2, this.validDate, x509Certificate1, publicKey, vector1, vector2, i);
        } catch (CertPathReviewerException certPathReviewerException) {
          addError(certPathReviewerException.getErrorMessage(), i);
        } 
      } 
      if (x500Principal2 != null && !x509Certificate2.getIssuerX500Principal().equals(x500Principal2)) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.certWrongIssuer", new Object[] { x500Principal2.getName(), x509Certificate2.getIssuerX500Principal().getName() });
        addError(errorBundle1, i);
      } 
      if (j != this.n) {
        if (x509Certificate2 != null && x509Certificate2.getVersion() == 1) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noCACert");
          addError(errorBundle1, i);
        } 
        try {
          BasicConstraints basicConstraints = BasicConstraints.getInstance(getExtensionValue(x509Certificate2, BASIC_CONSTRAINTS));
          if (basicConstraints != null) {
            if (!basicConstraints.isCA()) {
              ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noCACert");
              addError(errorBundle1, i);
            } 
          } else {
            ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noBasicConstraints");
            addError(errorBundle1, i);
          } 
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.errorProcesingBC");
          addError(errorBundle1, i);
        } 
        boolean[] arrayOfBoolean = x509Certificate2.getKeyUsage();
        if (arrayOfBoolean != null && (arrayOfBoolean.length <= 5 || !arrayOfBoolean[5])) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noCertSign");
          addError(errorBundle1, i);
        } 
      } 
      x509Certificate1 = x509Certificate2;
      x500Principal2 = x509Certificate2.getSubjectX500Principal();
      try {
        publicKey = getNextWorkingKey(this.certs, i);
        algorithmIdentifier = getAlgorithmIdentifier(publicKey);
        aSN1ObjectIdentifier = algorithmIdentifier.getAlgorithm();
        aSN1Encodable = algorithmIdentifier.getParameters();
      } catch (CertPathValidatorException certPathValidatorException) {
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.pubKeyError");
        addError(errorBundle1, i);
        algorithmIdentifier = null;
        aSN1ObjectIdentifier = null;
        aSN1Encodable = null;
      } 
    } 
    this.trustAnchor = trustAnchor;
    this.subjectPublicKey = publicKey;
  }
  
  private void checkPolicy() {
    int i;
    int j;
    int k;
    Set<String> set1 = this.pkixParams.getInitialPolicies();
    ArrayList[] arrayOfArrayList = new ArrayList[this.n + 1];
    for (byte b = 0; b < arrayOfArrayList.length; b++)
      arrayOfArrayList[b] = new ArrayList(); 
    HashSet<String> hashSet = new HashSet();
    hashSet.add("2.5.29.32.0");
    PKIXPolicyNode pKIXPolicyNode = new PKIXPolicyNode(new ArrayList(), 0, hashSet, null, new HashSet(), "2.5.29.32.0", false);
    arrayOfArrayList[0].add(pKIXPolicyNode);
    if (this.pkixParams.isExplicitPolicyRequired()) {
      i = 0;
    } else {
      i = this.n + 1;
    } 
    if (this.pkixParams.isAnyPolicyInhibited()) {
      j = 0;
    } else {
      j = this.n + 1;
    } 
    if (this.pkixParams.isPolicyMappingInhibited()) {
      k = 0;
    } else {
      k = this.n + 1;
    } 
    Set<String> set2 = null;
    X509Certificate x509Certificate = null;
    try {
      PKIXPolicyNode pKIXPolicyNode1;
      int m;
      for (m = this.certs.size() - 1; m >= 0; m--) {
        ASN1Sequence aSN1Sequence;
        int n = this.n - m;
        x509Certificate = this.certs.get(m);
        try {
          aSN1Sequence = (ASN1Sequence)getExtensionValue(x509Certificate, CERTIFICATE_POLICIES);
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyExtError");
          throw new CertPathReviewerException(errorBundle, annotatedException, this.certPath, m);
        } 
        if (aSN1Sequence != null && pKIXPolicyNode != null) {
          Enumeration enumeration = aSN1Sequence.getObjects();
          HashSet<String> hashSet1 = new HashSet();
          while (enumeration.hasMoreElements()) {
            PolicyInformation policyInformation = PolicyInformation.getInstance(enumeration.nextElement());
            ASN1ObjectIdentifier aSN1ObjectIdentifier = policyInformation.getPolicyIdentifier();
            hashSet1.add(aSN1ObjectIdentifier.getId());
            if (!"2.5.29.32.0".equals(aSN1ObjectIdentifier.getId())) {
              Set set3;
              try {
                set3 = getQualifierSet(policyInformation.getPolicyQualifiers());
              } catch (CertPathValidatorException certPathValidatorException) {
                ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyQualifierError");
                throw new CertPathReviewerException(errorBundle, certPathValidatorException, this.certPath, m);
              } 
              boolean bool = processCertD1i(n, (List[])arrayOfArrayList, aSN1ObjectIdentifier, set3);
              if (!bool)
                processCertD1ii(n, (List[])arrayOfArrayList, aSN1ObjectIdentifier, set3); 
            } 
          } 
          if (set2 == null || set2.contains("2.5.29.32.0")) {
            set2 = hashSet1;
          } else {
            Iterator<String> iterator = set2.iterator();
            HashSet<String> hashSet2 = new HashSet();
            while (iterator.hasNext()) {
              Object object = iterator.next();
              if (hashSet1.contains(object))
                hashSet2.add(object); 
            } 
            set2 = hashSet2;
          } 
          if (j > 0 || (n < this.n && isSelfIssued(x509Certificate))) {
            enumeration = aSN1Sequence.getObjects();
            while (enumeration.hasMoreElements()) {
              PolicyInformation policyInformation = PolicyInformation.getInstance(enumeration.nextElement());
              if ("2.5.29.32.0".equals(policyInformation.getPolicyIdentifier().getId())) {
                Set set3;
                try {
                  set3 = getQualifierSet(policyInformation.getPolicyQualifiers());
                } catch (CertPathValidatorException certPathValidatorException) {
                  ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyQualifierError");
                  throw new CertPathReviewerException(errorBundle, certPathValidatorException, this.certPath, m);
                } 
                ArrayList<PKIXPolicyNode> arrayList = arrayOfArrayList[n - 1];
                for (byte b1 = 0; b1 < arrayList.size(); b1++) {
                  PKIXPolicyNode pKIXPolicyNode2 = arrayList.get(b1);
                  for (String str1 : pKIXPolicyNode2.getExpectedPolicies()) {
                    String str2;
                    if (str1 instanceof String) {
                      str2 = str1;
                    } else if (str1 instanceof ASN1ObjectIdentifier) {
                      str2 = ((ASN1ObjectIdentifier)str1).getId();
                    } else {
                      continue;
                    } 
                    boolean bool = false;
                    Iterator<PKIXPolicyNode> iterator = pKIXPolicyNode2.getChildren();
                    while (iterator.hasNext()) {
                      PKIXPolicyNode pKIXPolicyNode3 = iterator.next();
                      if (str2.equals(pKIXPolicyNode3.getValidPolicy()))
                        bool = true; 
                    } 
                    if (!bool) {
                      HashSet<String> hashSet2 = new HashSet();
                      hashSet2.add(str2);
                      PKIXPolicyNode pKIXPolicyNode3 = new PKIXPolicyNode(new ArrayList(), n, hashSet2, pKIXPolicyNode2, set3, str2, false);
                      pKIXPolicyNode2.addChild(pKIXPolicyNode3);
                      arrayOfArrayList[n].add(pKIXPolicyNode3);
                    } 
                  } 
                } 
                break;
              } 
            } 
          } 
          for (int i1 = n - 1; i1 >= 0; i1--) {
            ArrayList<PKIXPolicyNode> arrayList = arrayOfArrayList[i1];
            for (byte b1 = 0; b1 < arrayList.size(); b1++) {
              PKIXPolicyNode pKIXPolicyNode2 = arrayList.get(b1);
              if (!pKIXPolicyNode2.hasChildren()) {
                pKIXPolicyNode = removePolicyNode(pKIXPolicyNode, (List[])arrayOfArrayList, pKIXPolicyNode2);
                if (pKIXPolicyNode == null)
                  break; 
              } 
            } 
          } 
          Set<String> set = x509Certificate.getCriticalExtensionOIDs();
          if (set != null) {
            boolean bool = set.contains(CERTIFICATE_POLICIES);
            ArrayList<PKIXPolicyNode> arrayList = arrayOfArrayList[n];
            for (byte b1 = 0; b1 < arrayList.size(); b1++) {
              PKIXPolicyNode pKIXPolicyNode2 = arrayList.get(b1);
              pKIXPolicyNode2.setCritical(bool);
            } 
          } 
        } 
        if (aSN1Sequence == null)
          pKIXPolicyNode = null; 
        if (i <= 0 && pKIXPolicyNode == null) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noValidPolicyTree");
          throw new CertPathReviewerException(errorBundle);
        } 
        if (n != this.n) {
          ASN1Primitive aSN1Primitive;
          try {
            aSN1Primitive = getExtensionValue(x509Certificate, POLICY_MAPPINGS);
          } catch (AnnotatedException annotatedException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyMapExtError");
            throw new CertPathReviewerException(errorBundle, annotatedException, this.certPath, m);
          } 
          if (aSN1Primitive != null) {
            ASN1Sequence aSN1Sequence1 = (ASN1Sequence)aSN1Primitive;
            for (byte b1 = 0; b1 < aSN1Sequence1.size(); b1++) {
              ASN1Sequence aSN1Sequence2 = (ASN1Sequence)aSN1Sequence1.getObjectAt(b1);
              ASN1ObjectIdentifier aSN1ObjectIdentifier1 = (ASN1ObjectIdentifier)aSN1Sequence2.getObjectAt(0);
              ASN1ObjectIdentifier aSN1ObjectIdentifier2 = (ASN1ObjectIdentifier)aSN1Sequence2.getObjectAt(1);
              if ("2.5.29.32.0".equals(aSN1ObjectIdentifier1.getId())) {
                ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.invalidPolicyMapping");
                throw new CertPathReviewerException(errorBundle, this.certPath, m);
              } 
              if ("2.5.29.32.0".equals(aSN1ObjectIdentifier2.getId())) {
                ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.invalidPolicyMapping");
                throw new CertPathReviewerException(errorBundle, this.certPath, m);
              } 
            } 
          } 
          if (aSN1Primitive != null) {
            ASN1Sequence aSN1Sequence1 = (ASN1Sequence)aSN1Primitive;
            HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
            HashSet<String> hashSet1 = new HashSet();
            for (byte b1 = 0; b1 < aSN1Sequence1.size(); b1++) {
              ASN1Sequence aSN1Sequence2 = (ASN1Sequence)aSN1Sequence1.getObjectAt(b1);
              String str1 = ((ASN1ObjectIdentifier)aSN1Sequence2.getObjectAt(0)).getId();
              String str2 = ((ASN1ObjectIdentifier)aSN1Sequence2.getObjectAt(1)).getId();
              if (!hashMap.containsKey(str1)) {
                HashSet<String> hashSet2 = new HashSet();
                hashSet2.add(str2);
                hashMap.put(str1, hashSet2);
                hashSet1.add(str1);
              } else {
                Set<String> set = (Set)hashMap.get(str1);
                set.add(str2);
              } 
            } 
            for (String str : hashSet1) {
              if (k > 0) {
                try {
                  prepareNextCertB1(n, (List[])arrayOfArrayList, str, hashMap, x509Certificate);
                } catch (AnnotatedException annotatedException) {
                  ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyExtError");
                  throw new CertPathReviewerException(errorBundle, annotatedException, this.certPath, m);
                } catch (CertPathValidatorException certPathValidatorException) {
                  ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyQualifierError");
                  throw new CertPathReviewerException(errorBundle, certPathValidatorException, this.certPath, m);
                } 
                continue;
              } 
              if (k <= 0)
                pKIXPolicyNode = prepareNextCertB2(n, (List[])arrayOfArrayList, str, pKIXPolicyNode); 
            } 
          } 
          if (!isSelfIssued(x509Certificate)) {
            if (i != 0)
              i--; 
            if (k != 0)
              k--; 
            if (j != 0)
              j--; 
          } 
          try {
            ASN1Sequence aSN1Sequence1 = (ASN1Sequence)getExtensionValue(x509Certificate, POLICY_CONSTRAINTS);
            if (aSN1Sequence1 != null) {
              Enumeration<ASN1TaggedObject> enumeration = aSN1Sequence1.getObjects();
              while (enumeration.hasMoreElements()) {
                int i1;
                ASN1TaggedObject aSN1TaggedObject = enumeration.nextElement();
                switch (aSN1TaggedObject.getTagNo()) {
                  case 0:
                    i1 = ASN1Integer.getInstance(aSN1TaggedObject, false).intValueExact();
                    if (i1 < i)
                      i = i1; 
                  case 1:
                    i1 = ASN1Integer.getInstance(aSN1TaggedObject, false).intValueExact();
                    if (i1 < k)
                      k = i1; 
                } 
              } 
            } 
          } catch (AnnotatedException annotatedException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyConstExtError");
            throw new CertPathReviewerException(errorBundle, this.certPath, m);
          } 
          try {
            ASN1Integer aSN1Integer = (ASN1Integer)getExtensionValue(x509Certificate, INHIBIT_ANY_POLICY);
            if (aSN1Integer != null) {
              int i1 = aSN1Integer.intValueExact();
              if (i1 < j)
                j = i1; 
            } 
          } catch (AnnotatedException annotatedException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyInhibitExtError");
            throw new CertPathReviewerException(errorBundle, this.certPath, m);
          } 
        } 
      } 
      if (!isSelfIssued(x509Certificate) && i > 0)
        i--; 
      try {
        ASN1Sequence aSN1Sequence = (ASN1Sequence)getExtensionValue(x509Certificate, POLICY_CONSTRAINTS);
        if (aSN1Sequence != null) {
          Enumeration<ASN1TaggedObject> enumeration = aSN1Sequence.getObjects();
          while (enumeration.hasMoreElements()) {
            int n;
            ASN1TaggedObject aSN1TaggedObject = enumeration.nextElement();
            switch (aSN1TaggedObject.getTagNo()) {
              case 0:
                n = ASN1Integer.getInstance(aSN1TaggedObject, false).intValueExact();
                if (n == 0)
                  i = 0; 
            } 
          } 
        } 
      } catch (AnnotatedException annotatedException) {
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.policyConstExtError");
        throw new CertPathReviewerException(errorBundle, this.certPath, m);
      } 
      if (pKIXPolicyNode == null) {
        if (this.pkixParams.isExplicitPolicyRequired()) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.explicitPolicy");
          throw new CertPathReviewerException(errorBundle, this.certPath, m);
        } 
        pKIXPolicyNode1 = null;
      } else if (isAnyPolicy(set1)) {
        if (this.pkixParams.isExplicitPolicyRequired()) {
          if (set2.isEmpty()) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.explicitPolicy");
            throw new CertPathReviewerException(errorBundle, this.certPath, m);
          } 
          HashSet hashSet1 = new HashSet();
          for (byte b1 = 0; b1 < arrayOfArrayList.length; b1++) {
            ArrayList<PKIXPolicyNode> arrayList = arrayOfArrayList[b1];
            for (byte b2 = 0; b2 < arrayList.size(); b2++) {
              PKIXPolicyNode pKIXPolicyNode2 = arrayList.get(b2);
              if ("2.5.29.32.0".equals(pKIXPolicyNode2.getValidPolicy())) {
                Iterator iterator = pKIXPolicyNode2.getChildren();
                while (iterator.hasNext())
                  hashSet1.add(iterator.next()); 
              } 
            } 
          } 
          for (PKIXPolicyNode pKIXPolicyNode2 : hashSet1) {
            String str = pKIXPolicyNode2.getValidPolicy();
            if (!set2.contains(str));
          } 
          if (pKIXPolicyNode != null)
            for (int n = this.n - 1; n >= 0; n--) {
              ArrayList<PKIXPolicyNode> arrayList = arrayOfArrayList[n];
              for (byte b2 = 0; b2 < arrayList.size(); b2++) {
                PKIXPolicyNode pKIXPolicyNode2 = arrayList.get(b2);
                if (!pKIXPolicyNode2.hasChildren())
                  pKIXPolicyNode = removePolicyNode(pKIXPolicyNode, (List[])arrayOfArrayList, pKIXPolicyNode2); 
              } 
            }  
        } 
        pKIXPolicyNode1 = pKIXPolicyNode;
      } else {
        HashSet<PKIXPolicyNode> hashSet1 = new HashSet();
        for (byte b1 = 0; b1 < arrayOfArrayList.length; b1++) {
          ArrayList<PKIXPolicyNode> arrayList = arrayOfArrayList[b1];
          for (byte b2 = 0; b2 < arrayList.size(); b2++) {
            PKIXPolicyNode pKIXPolicyNode2 = arrayList.get(b2);
            if ("2.5.29.32.0".equals(pKIXPolicyNode2.getValidPolicy())) {
              Iterator<PKIXPolicyNode> iterator = pKIXPolicyNode2.getChildren();
              while (iterator.hasNext()) {
                PKIXPolicyNode pKIXPolicyNode3 = iterator.next();
                if (!"2.5.29.32.0".equals(pKIXPolicyNode3.getValidPolicy()))
                  hashSet1.add(pKIXPolicyNode3); 
              } 
            } 
          } 
        } 
        for (PKIXPolicyNode pKIXPolicyNode2 : hashSet1) {
          String str = pKIXPolicyNode2.getValidPolicy();
          if (!set1.contains(str))
            pKIXPolicyNode = removePolicyNode(pKIXPolicyNode, (List[])arrayOfArrayList, pKIXPolicyNode2); 
        } 
        if (pKIXPolicyNode != null)
          for (int n = this.n - 1; n >= 0; n--) {
            ArrayList<PKIXPolicyNode> arrayList = arrayOfArrayList[n];
            for (byte b2 = 0; b2 < arrayList.size(); b2++) {
              PKIXPolicyNode pKIXPolicyNode2 = arrayList.get(b2);
              if (!pKIXPolicyNode2.hasChildren())
                pKIXPolicyNode = removePolicyNode(pKIXPolicyNode, (List[])arrayOfArrayList, pKIXPolicyNode2); 
            } 
          }  
        pKIXPolicyNode1 = pKIXPolicyNode;
      } 
      if (i <= 0 && pKIXPolicyNode1 == null) {
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.invalidPolicy");
        throw new CertPathReviewerException(errorBundle);
      } 
      pKIXPolicyNode = pKIXPolicyNode1;
    } catch (CertPathReviewerException certPathReviewerException) {
      addError(certPathReviewerException.getErrorMessage(), certPathReviewerException.getIndex());
      pKIXPolicyNode = null;
    } 
  }
  
  private void checkCriticalExtensions() {
    // Byte code:
    //   0: aload_0
    //   1: getfield pkixParams : Ljava/security/cert/PKIXParameters;
    //   4: invokevirtual getCertPathCheckers : ()Ljava/util/List;
    //   7: astore_1
    //   8: aload_1
    //   9: invokeinterface iterator : ()Ljava/util/Iterator;
    //   14: astore_2
    //   15: aload_2
    //   16: invokeinterface hasNext : ()Z
    //   21: ifeq -> 40
    //   24: aload_2
    //   25: invokeinterface next : ()Ljava/lang/Object;
    //   30: checkcast java/security/cert/PKIXCertPathChecker
    //   33: iconst_0
    //   34: invokevirtual init : (Z)V
    //   37: goto -> 15
    //   40: goto -> 94
    //   43: astore_3
    //   44: new org/bouncycastle/i18n/ErrorBundle
    //   47: dup
    //   48: ldc 'org.bouncycastle.x509.CertPathReviewerMessages'
    //   50: ldc_w 'CertPathReviewer.certPathCheckerError'
    //   53: iconst_3
    //   54: anewarray java/lang/Object
    //   57: dup
    //   58: iconst_0
    //   59: aload_3
    //   60: invokevirtual getMessage : ()Ljava/lang/String;
    //   63: aastore
    //   64: dup
    //   65: iconst_1
    //   66: aload_3
    //   67: aastore
    //   68: dup
    //   69: iconst_2
    //   70: aload_3
    //   71: invokevirtual getClass : ()Ljava/lang/Class;
    //   74: invokevirtual getName : ()Ljava/lang/String;
    //   77: aastore
    //   78: invokespecial <init> : (Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    //   81: astore #4
    //   83: new org/bouncycastle/x509/CertPathReviewerException
    //   86: dup
    //   87: aload #4
    //   89: aload_3
    //   90: invokespecial <init> : (Lorg/bouncycastle/i18n/ErrorBundle;Ljava/lang/Throwable;)V
    //   93: athrow
    //   94: aconst_null
    //   95: astore_3
    //   96: aload_0
    //   97: getfield certs : Ljava/util/List;
    //   100: invokeinterface size : ()I
    //   105: iconst_1
    //   106: isub
    //   107: istore #4
    //   109: iload #4
    //   111: iflt -> 502
    //   114: aload_0
    //   115: getfield certs : Ljava/util/List;
    //   118: iload #4
    //   120: invokeinterface get : (I)Ljava/lang/Object;
    //   125: checkcast java/security/cert/X509Certificate
    //   128: astore_3
    //   129: aload_3
    //   130: invokevirtual getCriticalExtensionOIDs : ()Ljava/util/Set;
    //   133: astore #5
    //   135: aload #5
    //   137: ifnull -> 496
    //   140: aload #5
    //   142: invokeinterface isEmpty : ()Z
    //   147: ifeq -> 153
    //   150: goto -> 496
    //   153: aload #5
    //   155: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.KEY_USAGE : Ljava/lang/String;
    //   158: invokeinterface remove : (Ljava/lang/Object;)Z
    //   163: pop
    //   164: aload #5
    //   166: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.CERTIFICATE_POLICIES : Ljava/lang/String;
    //   169: invokeinterface remove : (Ljava/lang/Object;)Z
    //   174: pop
    //   175: aload #5
    //   177: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.POLICY_MAPPINGS : Ljava/lang/String;
    //   180: invokeinterface remove : (Ljava/lang/Object;)Z
    //   185: pop
    //   186: aload #5
    //   188: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.INHIBIT_ANY_POLICY : Ljava/lang/String;
    //   191: invokeinterface remove : (Ljava/lang/Object;)Z
    //   196: pop
    //   197: aload #5
    //   199: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.ISSUING_DISTRIBUTION_POINT : Ljava/lang/String;
    //   202: invokeinterface remove : (Ljava/lang/Object;)Z
    //   207: pop
    //   208: aload #5
    //   210: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.DELTA_CRL_INDICATOR : Ljava/lang/String;
    //   213: invokeinterface remove : (Ljava/lang/Object;)Z
    //   218: pop
    //   219: aload #5
    //   221: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.POLICY_CONSTRAINTS : Ljava/lang/String;
    //   224: invokeinterface remove : (Ljava/lang/Object;)Z
    //   229: pop
    //   230: aload #5
    //   232: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.BASIC_CONSTRAINTS : Ljava/lang/String;
    //   235: invokeinterface remove : (Ljava/lang/Object;)Z
    //   240: pop
    //   241: aload #5
    //   243: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.SUBJECT_ALTERNATIVE_NAME : Ljava/lang/String;
    //   246: invokeinterface remove : (Ljava/lang/Object;)Z
    //   251: pop
    //   252: aload #5
    //   254: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.NAME_CONSTRAINTS : Ljava/lang/String;
    //   257: invokeinterface remove : (Ljava/lang/Object;)Z
    //   262: pop
    //   263: iload #4
    //   265: ifne -> 282
    //   268: aload #5
    //   270: getstatic org/bouncycastle/asn1/x509/Extension.extendedKeyUsage : Lorg/bouncycastle/asn1/ASN1ObjectIdentifier;
    //   273: invokevirtual getId : ()Ljava/lang/String;
    //   276: invokeinterface remove : (Ljava/lang/Object;)Z
    //   281: pop
    //   282: aload #5
    //   284: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.QC_STATEMENT : Ljava/lang/String;
    //   287: invokeinterface contains : (Ljava/lang/Object;)Z
    //   292: ifeq -> 316
    //   295: aload_0
    //   296: aload_3
    //   297: iload #4
    //   299: invokespecial processQcStatements : (Ljava/security/cert/X509Certificate;I)Z
    //   302: ifeq -> 316
    //   305: aload #5
    //   307: getstatic org/bouncycastle/x509/PKIXCertPathReviewer.QC_STATEMENT : Ljava/lang/String;
    //   310: invokeinterface remove : (Ljava/lang/Object;)Z
    //   315: pop
    //   316: aload_1
    //   317: invokeinterface iterator : ()Ljava/util/Iterator;
    //   322: astore #6
    //   324: aload #6
    //   326: invokeinterface hasNext : ()Z
    //   331: ifeq -> 418
    //   334: aload #6
    //   336: invokeinterface next : ()Ljava/lang/Object;
    //   341: checkcast java/security/cert/PKIXCertPathChecker
    //   344: aload_3
    //   345: aload #5
    //   347: invokevirtual check : (Ljava/security/cert/Certificate;Ljava/util/Collection;)V
    //   350: goto -> 324
    //   353: astore #7
    //   355: new org/bouncycastle/i18n/ErrorBundle
    //   358: dup
    //   359: ldc 'org.bouncycastle.x509.CertPathReviewerMessages'
    //   361: ldc_w 'CertPathReviewer.criticalExtensionError'
    //   364: iconst_3
    //   365: anewarray java/lang/Object
    //   368: dup
    //   369: iconst_0
    //   370: aload #7
    //   372: invokevirtual getMessage : ()Ljava/lang/String;
    //   375: aastore
    //   376: dup
    //   377: iconst_1
    //   378: aload #7
    //   380: aastore
    //   381: dup
    //   382: iconst_2
    //   383: aload #7
    //   385: invokevirtual getClass : ()Ljava/lang/Class;
    //   388: invokevirtual getName : ()Ljava/lang/String;
    //   391: aastore
    //   392: invokespecial <init> : (Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    //   395: astore #8
    //   397: new org/bouncycastle/x509/CertPathReviewerException
    //   400: dup
    //   401: aload #8
    //   403: aload #7
    //   405: invokevirtual getCause : ()Ljava/lang/Throwable;
    //   408: aload_0
    //   409: getfield certPath : Ljava/security/cert/CertPath;
    //   412: iload #4
    //   414: invokespecial <init> : (Lorg/bouncycastle/i18n/ErrorBundle;Ljava/lang/Throwable;Ljava/security/cert/CertPath;I)V
    //   417: athrow
    //   418: aload #5
    //   420: invokeinterface isEmpty : ()Z
    //   425: ifne -> 496
    //   428: aload #5
    //   430: invokeinterface iterator : ()Ljava/util/Iterator;
    //   435: astore #8
    //   437: aload #8
    //   439: invokeinterface hasNext : ()Z
    //   444: ifeq -> 496
    //   447: new org/bouncycastle/i18n/ErrorBundle
    //   450: dup
    //   451: ldc 'org.bouncycastle.x509.CertPathReviewerMessages'
    //   453: ldc_w 'CertPathReviewer.unknownCriticalExt'
    //   456: iconst_1
    //   457: anewarray java/lang/Object
    //   460: dup
    //   461: iconst_0
    //   462: new org/bouncycastle/asn1/ASN1ObjectIdentifier
    //   465: dup
    //   466: aload #8
    //   468: invokeinterface next : ()Ljava/lang/Object;
    //   473: checkcast java/lang/String
    //   476: invokespecial <init> : (Ljava/lang/String;)V
    //   479: aastore
    //   480: invokespecial <init> : (Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    //   483: astore #7
    //   485: aload_0
    //   486: aload #7
    //   488: iload #4
    //   490: invokevirtual addError : (Lorg/bouncycastle/i18n/ErrorBundle;I)V
    //   493: goto -> 437
    //   496: iinc #4, -1
    //   499: goto -> 109
    //   502: goto -> 518
    //   505: astore_3
    //   506: aload_0
    //   507: aload_3
    //   508: invokevirtual getErrorMessage : ()Lorg/bouncycastle/i18n/ErrorBundle;
    //   511: aload_3
    //   512: invokevirtual getIndex : ()I
    //   515: invokevirtual addError : (Lorg/bouncycastle/i18n/ErrorBundle;I)V
    //   518: return
    // Exception table:
    //   from	to	target	type
    //   15	40	43	java/security/cert/CertPathValidatorException
    //   15	502	505	org/bouncycastle/x509/CertPathReviewerException
    //   334	350	353	java/security/cert/CertPathValidatorException
  }
  
  private boolean processQcStatements(X509Certificate paramX509Certificate, int paramInt) {
    try {
      boolean bool = false;
      ASN1Sequence aSN1Sequence = (ASN1Sequence)getExtensionValue(paramX509Certificate, QC_STATEMENT);
      for (byte b = 0; b < aSN1Sequence.size(); b++) {
        QCStatement qCStatement = QCStatement.getInstance(aSN1Sequence.getObjectAt(b));
        if (QCStatement.id_etsi_qcs_QcCompliance.equals(qCStatement.getStatementId())) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.QcEuCompliance");
          addNotification(errorBundle, paramInt);
        } else if (!QCStatement.id_qcs_pkixQCSyntax_v1.equals(qCStatement.getStatementId())) {
          if (QCStatement.id_etsi_qcs_QcSSCD.equals(qCStatement.getStatementId())) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.QcSSCD");
            addNotification(errorBundle, paramInt);
          } else if (QCStatement.id_etsi_qcs_LimiteValue.equals(qCStatement.getStatementId())) {
            ErrorBundle errorBundle;
            MonetaryValue monetaryValue = MonetaryValue.getInstance(qCStatement.getStatementInfo());
            Iso4217CurrencyCode iso4217CurrencyCode = monetaryValue.getCurrency();
            double d = monetaryValue.getAmount().doubleValue() * Math.pow(10.0D, monetaryValue.getExponent().doubleValue());
            if (monetaryValue.getCurrency().isAlphabetic()) {
              errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.QcLimitValueAlpha", new Object[] { monetaryValue.getCurrency().getAlphabetic(), new TrustedInput(new Double(d)), monetaryValue });
            } else {
              errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.QcLimitValueNum", new Object[] { Integers.valueOf(monetaryValue.getCurrency().getNumeric()), new TrustedInput(new Double(d)), monetaryValue });
            } 
            addNotification(errorBundle, paramInt);
          } else {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.QcUnknownStatement", new Object[] { qCStatement.getStatementId(), new UntrustedInput(qCStatement) });
            addNotification(errorBundle, paramInt);
            bool = true;
          } 
        } 
      } 
      return !bool;
    } catch (AnnotatedException annotatedException) {
      ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.QcStatementExtError");
      addError(errorBundle, paramInt);
      return false;
    } 
  }
  
  private String IPtoString(byte[] paramArrayOfbyte) {
    String str;
    try {
      str = InetAddress.getByAddress(paramArrayOfbyte).getHostAddress();
    } catch (Exception exception) {
      StringBuffer stringBuffer = new StringBuffer();
      for (byte b = 0; b != paramArrayOfbyte.length; b++) {
        stringBuffer.append(Integer.toHexString(paramArrayOfbyte[b] & 0xFF));
        stringBuffer.append(' ');
      } 
      str = stringBuffer.toString();
    } 
    return str;
  }
  
  protected void checkRevocation(PKIXParameters paramPKIXParameters, X509Certificate paramX509Certificate1, Date paramDate, X509Certificate paramX509Certificate2, PublicKey paramPublicKey, Vector paramVector1, Vector paramVector2, int paramInt) throws CertPathReviewerException {
    checkCRLs(paramPKIXParameters, paramX509Certificate1, paramDate, paramX509Certificate2, paramPublicKey, paramVector1, paramInt);
  }
  
  protected void checkCRLs(PKIXParameters paramPKIXParameters, X509Certificate paramX509Certificate1, Date paramDate, X509Certificate paramX509Certificate2, PublicKey paramPublicKey, Vector paramVector, int paramInt) throws CertPathReviewerException {
    Iterator<?> iterator;
    X509CRLStoreSelector x509CRLStoreSelector = new X509CRLStoreSelector();
    try {
      x509CRLStoreSelector.addIssuerName(getEncodedIssuerPrincipal(paramX509Certificate1).getEncoded());
    } catch (IOException iOException) {
      ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlIssuerException");
      throw new CertPathReviewerException(errorBundle, iOException);
    } 
    x509CRLStoreSelector.setCertificateChecking(paramX509Certificate1);
    try {
      Set set = PKIXCRLUtil.findCRLs(x509CRLStoreSelector, paramPKIXParameters);
      iterator = set.iterator();
      if (set.isEmpty()) {
        set = PKIXCRLUtil.findCRLs(new X509CRLStoreSelector(), paramPKIXParameters);
        Iterator<X509CRL> iterator1 = set.iterator();
        ArrayList<X500Principal> arrayList = new ArrayList();
        while (iterator1.hasNext())
          arrayList.add(((X509CRL)iterator1.next()).getIssuerX500Principal()); 
        int i = arrayList.size();
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noCrlInCertstore", new Object[] { new UntrustedInput(x509CRLStoreSelector.getIssuerNames()), new UntrustedInput(arrayList), Integers.valueOf(i) });
        addNotification(errorBundle, paramInt);
      } 
    } catch (AnnotatedException annotatedException) {
      ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlExtractionError", new Object[] { annotatedException.getCause().getMessage(), annotatedException.getCause(), annotatedException.getCause().getClass().getName() });
      addError(errorBundle, paramInt);
      iterator = (new ArrayList()).iterator();
    } 
    boolean bool = false;
    X509CRL x509CRL = null;
    while (iterator.hasNext()) {
      x509CRL = (X509CRL)iterator.next();
      Date date1 = x509CRL.getThisUpdate();
      Date date2 = x509CRL.getNextUpdate();
      Object[] arrayOfObject = { new TrustedInput(date1), new TrustedInput(date2) };
      if (date2 == null || paramDate.before(date2)) {
        bool = true;
        ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.localValidCRL", arrayOfObject);
        addNotification(errorBundle1, paramInt);
        break;
      } 
      ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.localInvalidCRL", arrayOfObject);
      addNotification(errorBundle, paramInt);
    } 
    if (!bool) {
      X500Principal x500Principal = paramX509Certificate1.getIssuerX500Principal();
      X509CRL x509CRL1 = null;
      Iterator<String> iterator1 = paramVector.iterator();
      while (iterator1.hasNext()) {
        try {
          String str = iterator1.next();
          x509CRL1 = getCRL(str);
          if (x509CRL1 != null) {
            X500Principal x500Principal1 = x509CRL1.getIssuerX500Principal();
            if (!x500Principal.equals(x500Principal1)) {
              ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.onlineCRLWrongCA", new Object[] { new UntrustedInput(x500Principal1.getName()), new UntrustedInput(x500Principal.getName()), new UntrustedUrlInput(str) });
              addNotification(errorBundle1, paramInt);
              continue;
            } 
            Date date1 = x509CRL1.getThisUpdate();
            Date date2 = x509CRL1.getNextUpdate();
            Object[] arrayOfObject = { new TrustedInput(date1), new TrustedInput(date2), new UntrustedUrlInput(str) };
            if (date2 == null || paramDate.before(date2)) {
              bool = true;
              ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.onlineValidCRL", arrayOfObject);
              addNotification(errorBundle1, paramInt);
              x509CRL = x509CRL1;
              break;
            } 
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.onlineInvalidCRL", arrayOfObject);
            addNotification(errorBundle, paramInt);
          } 
        } catch (CertPathReviewerException certPathReviewerException) {
          addNotification(certPathReviewerException.getErrorMessage(), paramInt);
        } 
      } 
    } 
    if (x509CRL != null) {
      ASN1Primitive aSN1Primitive1;
      ASN1Primitive aSN1Primitive2;
      if (paramX509Certificate2 != null) {
        boolean[] arrayOfBoolean = paramX509Certificate2.getKeyUsage();
        if (arrayOfBoolean != null && (arrayOfBoolean.length <= 6 || !arrayOfBoolean[6])) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noCrlSigningPermited");
          throw new CertPathReviewerException(errorBundle);
        } 
      } 
      if (paramPublicKey != null) {
        try {
          x509CRL.verify(paramPublicKey, "BC");
        } catch (Exception exception) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlVerifyFailed");
          throw new CertPathReviewerException(errorBundle, exception);
        } 
      } else {
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlNoIssuerPublicKey");
        throw new CertPathReviewerException(errorBundle);
      } 
      X509CRLEntry x509CRLEntry = x509CRL.getRevokedCertificate(paramX509Certificate1.getSerialNumber());
      if (x509CRLEntry != null) {
        String str = null;
        if (x509CRLEntry.hasExtensions()) {
          try {
            aSN1Primitive1 = ASN1Enumerated.getInstance(getExtensionValue(x509CRLEntry, Extension.reasonCode.getId()));
          } catch (AnnotatedException annotatedException) {
            ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlReasonExtError");
            throw new CertPathReviewerException(errorBundle1, annotatedException);
          } 
          if (aSN1Primitive1 != null)
            str = crlReasons[aSN1Primitive1.intValueExact()]; 
        } 
        if (str == null)
          str = crlReasons[7]; 
        LocaleString localeString = new LocaleString("org.bouncycastle.x509.CertPathReviewerMessages", str);
        if (!paramDate.before(x509CRLEntry.getRevocationDate())) {
          ErrorBundle errorBundle1 = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.certRevoked", new Object[] { new TrustedInput(x509CRLEntry.getRevocationDate()), localeString });
          throw new CertPathReviewerException(errorBundle1);
        } 
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.revokedAfterValidation", new Object[] { new TrustedInput(x509CRLEntry.getRevocationDate()), localeString });
        addNotification(errorBundle, paramInt);
      } else {
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.notRevoked");
        addNotification(errorBundle, paramInt);
      } 
      Date date = x509CRL.getNextUpdate();
      if (date != null && !paramDate.before(date)) {
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlUpdateAvailable", new Object[] { new TrustedInput(date) });
        addNotification(errorBundle, paramInt);
      } 
      try {
        aSN1Primitive1 = getExtensionValue(x509CRL, ISSUING_DISTRIBUTION_POINT);
      } catch (AnnotatedException annotatedException) {
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.distrPtExtError");
        throw new CertPathReviewerException(errorBundle);
      } 
      try {
        aSN1Primitive2 = getExtensionValue(x509CRL, DELTA_CRL_INDICATOR);
      } catch (AnnotatedException annotatedException) {
        ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.deltaCrlExtError");
        throw new CertPathReviewerException(errorBundle);
      } 
      if (aSN1Primitive2 != null) {
        Iterator<X509CRL> iterator1;
        X509CRLStoreSelector x509CRLStoreSelector1 = new X509CRLStoreSelector();
        try {
          x509CRLStoreSelector1.addIssuerName(getIssuerPrincipal(x509CRL).getEncoded());
        } catch (IOException iOException) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlIssuerException");
          throw new CertPathReviewerException(errorBundle, iOException);
        } 
        x509CRLStoreSelector1.setMinCRLNumber(((ASN1Integer)aSN1Primitive2).getPositiveValue());
        try {
          x509CRLStoreSelector1.setMaxCRLNumber(((ASN1Integer)getExtensionValue(x509CRL, CRL_NUMBER)).getPositiveValue().subtract(BigInteger.valueOf(1L)));
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlNbrExtError");
          throw new CertPathReviewerException(errorBundle, annotatedException);
        } 
        boolean bool1 = false;
        try {
          iterator1 = PKIXCRLUtil.findCRLs(x509CRLStoreSelector1, paramPKIXParameters).iterator();
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlExtractionError");
          throw new CertPathReviewerException(errorBundle, annotatedException);
        } 
        while (iterator1.hasNext()) {
          ASN1Primitive aSN1Primitive;
          X509CRL x509CRL1 = iterator1.next();
          try {
            aSN1Primitive = getExtensionValue(x509CRL1, ISSUING_DISTRIBUTION_POINT);
          } catch (AnnotatedException annotatedException) {
            ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.distrPtExtError");
            throw new CertPathReviewerException(errorBundle, annotatedException);
          } 
          if (Objects.areEqual(aSN1Primitive1, aSN1Primitive)) {
            bool1 = true;
            break;
          } 
        } 
        if (!bool1) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noBaseCRL");
          throw new CertPathReviewerException(errorBundle);
        } 
      } 
      if (aSN1Primitive1 != null) {
        IssuingDistributionPoint issuingDistributionPoint = IssuingDistributionPoint.getInstance(aSN1Primitive1);
        BasicConstraints basicConstraints = null;
        try {
          basicConstraints = BasicConstraints.getInstance(getExtensionValue(paramX509Certificate1, BASIC_CONSTRAINTS));
        } catch (AnnotatedException annotatedException) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlBCExtError");
          throw new CertPathReviewerException(errorBundle, annotatedException);
        } 
        if (issuingDistributionPoint.onlyContainsUserCerts() && basicConstraints != null && basicConstraints.isCA()) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlOnlyUserCert");
          throw new CertPathReviewerException(errorBundle);
        } 
        if (issuingDistributionPoint.onlyContainsCACerts() && (basicConstraints == null || !basicConstraints.isCA())) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlOnlyCaCert");
          throw new CertPathReviewerException(errorBundle);
        } 
        if (issuingDistributionPoint.onlyContainsAttributeCerts()) {
          ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.crlOnlyAttrCert");
          throw new CertPathReviewerException(errorBundle);
        } 
      } 
    } 
    if (!bool) {
      ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.noValidCrlFound");
      throw new CertPathReviewerException(errorBundle);
    } 
  }
  
  protected Vector getCRLDistUrls(CRLDistPoint paramCRLDistPoint) {
    Vector<String> vector = new Vector();
    if (paramCRLDistPoint != null) {
      DistributionPoint[] arrayOfDistributionPoint = paramCRLDistPoint.getDistributionPoints();
      for (byte b = 0; b < arrayOfDistributionPoint.length; b++) {
        DistributionPointName distributionPointName = arrayOfDistributionPoint[b].getDistributionPoint();
        if (distributionPointName.getType() == 0) {
          GeneralName[] arrayOfGeneralName = GeneralNames.getInstance(distributionPointName.getName()).getNames();
          for (byte b1 = 0; b1 < arrayOfGeneralName.length; b1++) {
            if (arrayOfGeneralName[b1].getTagNo() == 6) {
              String str = ((ASN1IA5String)arrayOfGeneralName[b1].getName()).getString();
              vector.add(str);
            } 
          } 
        } 
      } 
    } 
    return vector;
  }
  
  protected Vector getOCSPUrls(AuthorityInformationAccess paramAuthorityInformationAccess) {
    Vector<String> vector = new Vector();
    if (paramAuthorityInformationAccess != null) {
      AccessDescription[] arrayOfAccessDescription = paramAuthorityInformationAccess.getAccessDescriptions();
      for (byte b = 0; b < arrayOfAccessDescription.length; b++) {
        if (arrayOfAccessDescription[b].getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
          GeneralName generalName = arrayOfAccessDescription[b].getAccessLocation();
          if (generalName.getTagNo() == 6) {
            String str = ((ASN1IA5String)generalName.getName()).getString();
            vector.add(str);
          } 
        } 
      } 
    } 
    return vector;
  }
  
  private X509CRL getCRL(String paramString) throws CertPathReviewerException {
    X509CRL x509CRL = null;
    try {
      URL uRL = new URL(paramString);
      if (uRL.getProtocol().equals("http") || uRL.getProtocol().equals("https")) {
        HttpURLConnection httpURLConnection = (HttpURLConnection)uRL.openConnection();
        httpURLConnection.setUseCaches(false);
        httpURLConnection.setDoInput(true);
        httpURLConnection.connect();
        if (httpURLConnection.getResponseCode() == 200) {
          CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
          x509CRL = (X509CRL)certificateFactory.generateCRL(httpURLConnection.getInputStream());
        } else {
          throw new Exception(httpURLConnection.getResponseMessage());
        } 
      } 
    } catch (Exception exception) {
      ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.loadCrlDistPointError", new Object[] { new UntrustedInput(paramString), exception.getMessage(), exception, exception.getClass().getName() });
      throw new CertPathReviewerException(errorBundle);
    } 
    return x509CRL;
  }
  
  protected Collection getTrustAnchors(X509Certificate paramX509Certificate, Set paramSet) throws CertPathReviewerException {
    ArrayList<TrustAnchor> arrayList = new ArrayList();
    Iterator<TrustAnchor> iterator = paramSet.iterator();
    X509CertSelector x509CertSelector = new X509CertSelector();
    try {
      x509CertSelector.setSubject(getEncodedIssuerPrincipal(paramX509Certificate).getEncoded());
      byte[] arrayOfByte = paramX509Certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
      if (arrayOfByte != null) {
        ASN1OctetString aSN1OctetString = (ASN1OctetString)ASN1Primitive.fromByteArray(arrayOfByte);
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(ASN1Primitive.fromByteArray(aSN1OctetString.getOctets()));
        BigInteger bigInteger = authorityKeyIdentifier.getAuthorityCertSerialNumber();
        if (bigInteger != null)
          x509CertSelector.setSerialNumber(authorityKeyIdentifier.getAuthorityCertSerialNumber()); 
      } 
    } catch (IOException iOException) {
      ErrorBundle errorBundle = new ErrorBundle("org.bouncycastle.x509.CertPathReviewerMessages", "CertPathReviewer.trustAnchorIssuerError");
      throw new CertPathReviewerException(errorBundle);
    } 
    while (iterator.hasNext()) {
      TrustAnchor trustAnchor = iterator.next();
      if (trustAnchor.getTrustedCert() != null) {
        if (x509CertSelector.match(trustAnchor.getTrustedCert()))
          arrayList.add(trustAnchor); 
        continue;
      } 
      if (trustAnchor.getCAName() != null && trustAnchor.getCAPublicKey() != null) {
        X500Principal x500Principal1 = getEncodedIssuerPrincipal(paramX509Certificate);
        X500Principal x500Principal2 = new X500Principal(trustAnchor.getCAName());
        if (x500Principal1.equals(x500Principal2))
          arrayList.add(trustAnchor); 
      } 
    } 
    return arrayList;
  }
}
