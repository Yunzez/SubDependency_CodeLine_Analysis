package org.bouncycastle.jce.provider;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.isismtt.ISISMTTObjectIdentifiers;
import org.bouncycastle.jcajce.PKIXCRLStore;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.PKIXCertStore;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jcajce.PKIXExtendedBuilderParameters;
import org.bouncycastle.jcajce.PKIXExtendedParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.exception.ExtCertPathBuilderException;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;
import org.bouncycastle.x509.X509AttributeCertificate;

class CertPathValidatorUtilities {
  protected static final String CERTIFICATE_POLICIES = Extension.certificatePolicies.getId();
  
  protected static final String BASIC_CONSTRAINTS = Extension.basicConstraints.getId();
  
  protected static final String POLICY_MAPPINGS = Extension.policyMappings.getId();
  
  protected static final String SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName.getId();
  
  protected static final String NAME_CONSTRAINTS = Extension.nameConstraints.getId();
  
  protected static final String KEY_USAGE = Extension.keyUsage.getId();
  
  protected static final String INHIBIT_ANY_POLICY = Extension.inhibitAnyPolicy.getId();
  
  protected static final String ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();
  
  protected static final String DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();
  
  protected static final String POLICY_CONSTRAINTS = Extension.policyConstraints.getId();
  
  protected static final String FRESHEST_CRL = Extension.freshestCRL.getId();
  
  protected static final String CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();
  
  protected static final String AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();
  
  protected static final String ANY_POLICY = "2.5.29.32.0";
  
  protected static final String CRL_NUMBER = Extension.cRLNumber.getId();
  
  protected static final int KEY_CERT_SIGN = 5;
  
  protected static final int CRL_SIGN = 6;
  
  protected static final String[] crlReasons = new String[] { 
      "unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", 
      "aACompromise" };
  
  static Collection findTargets(PKIXExtendedBuilderParameters paramPKIXExtendedBuilderParameters) throws CertPathBuilderException {
    PKIXExtendedParameters pKIXExtendedParameters = paramPKIXExtendedBuilderParameters.getBaseParameters();
    PKIXCertStoreSelector pKIXCertStoreSelector = pKIXExtendedParameters.getTargetConstraints();
    LinkedHashSet linkedHashSet = new LinkedHashSet();
    try {
      findCertificates(linkedHashSet, pKIXCertStoreSelector, pKIXExtendedParameters.getCertificateStores());
      findCertificates(linkedHashSet, pKIXCertStoreSelector, pKIXExtendedParameters.getCertStores());
    } catch (AnnotatedException annotatedException) {
      throw new ExtCertPathBuilderException("Error finding target certificate.", annotatedException);
    } 
    if (!linkedHashSet.isEmpty())
      return linkedHashSet; 
    Certificate certificate = pKIXCertStoreSelector.getCertificate();
    if (null == certificate)
      throw new CertPathBuilderException("No certificate found matching targetConstraints."); 
    return Collections.singleton(certificate);
  }
  
  protected static TrustAnchor findTrustAnchor(X509Certificate paramX509Certificate, Set paramSet) throws AnnotatedException {
    return findTrustAnchor(paramX509Certificate, paramSet, null);
  }
  
  protected static TrustAnchor findTrustAnchor(X509Certificate paramX509Certificate, Set paramSet, String paramString) throws AnnotatedException {
    TrustAnchor trustAnchor = null;
    PublicKey publicKey = null;
    Exception exception = null;
    X509CertSelector x509CertSelector = new X509CertSelector();
    X500Principal x500Principal = paramX509Certificate.getIssuerX500Principal();
    x509CertSelector.setSubject(x500Principal);
    X500Name x500Name = null;
    Iterator<TrustAnchor> iterator = paramSet.iterator();
    while (iterator.hasNext() && trustAnchor == null) {
      trustAnchor = iterator.next();
      if (trustAnchor.getTrustedCert() != null) {
        if (x509CertSelector.match(trustAnchor.getTrustedCert())) {
          publicKey = trustAnchor.getTrustedCert().getPublicKey();
        } else {
          trustAnchor = null;
        } 
      } else if (trustAnchor.getCA() != null && trustAnchor.getCAName() != null && trustAnchor.getCAPublicKey() != null) {
        if (x500Name == null)
          x500Name = X500Name.getInstance(x500Principal.getEncoded()); 
        try {
          X500Name x500Name1 = X500Name.getInstance(trustAnchor.getCA().getEncoded());
          if (x500Name.equals(x500Name1)) {
            publicKey = trustAnchor.getCAPublicKey();
          } else {
            trustAnchor = null;
          } 
        } catch (IllegalArgumentException illegalArgumentException) {
          trustAnchor = null;
        } 
      } else {
        trustAnchor = null;
      } 
      if (publicKey != null)
        try {
          verifyX509Certificate(paramX509Certificate, publicKey, paramString);
        } catch (Exception exception1) {
          exception = exception1;
          trustAnchor = null;
          publicKey = null;
        }  
    } 
    if (trustAnchor == null && exception != null)
      throw new AnnotatedException("TrustAnchor found but certificate validation failed.", exception); 
    return trustAnchor;
  }
  
  static boolean isIssuerTrustAnchor(X509Certificate paramX509Certificate, Set paramSet, String paramString) throws AnnotatedException {
    try {
      return (findTrustAnchor(paramX509Certificate, paramSet, paramString) != null);
    } catch (Exception exception) {
      return false;
    } 
  }
  
  static List<PKIXCertStore> getAdditionalStoresFromAltNames(byte[] paramArrayOfbyte, Map<GeneralName, PKIXCertStore> paramMap) throws CertificateParsingException {
    if (paramArrayOfbyte == null)
      return Collections.EMPTY_LIST; 
    GeneralNames generalNames = GeneralNames.getInstance(ASN1OctetString.getInstance(paramArrayOfbyte).getOctets());
    GeneralName[] arrayOfGeneralName = generalNames.getNames();
    ArrayList<PKIXCertStore> arrayList = new ArrayList();
    for (byte b = 0; b != arrayOfGeneralName.length; b++) {
      GeneralName generalName = arrayOfGeneralName[b];
      PKIXCertStore pKIXCertStore = paramMap.get(generalName);
      if (pKIXCertStore != null)
        arrayList.add(pKIXCertStore); 
    } 
    return arrayList;
  }
  
  protected static Date getValidityDate(PKIXExtendedParameters paramPKIXExtendedParameters, Date paramDate) {
    Date date = paramPKIXExtendedParameters.getValidityDate();
    return (null == date) ? paramDate : date;
  }
  
  protected static boolean isSelfIssued(X509Certificate paramX509Certificate) {
    return paramX509Certificate.getSubjectDN().equals(paramX509Certificate.getIssuerDN());
  }
  
  protected static ASN1Primitive getExtensionValue(X509Extension paramX509Extension, String paramString) throws AnnotatedException {
    byte[] arrayOfByte = paramX509Extension.getExtensionValue(paramString);
    return (null == arrayOfByte) ? null : getObject(paramString, arrayOfByte);
  }
  
  private static ASN1Primitive getObject(String paramString, byte[] paramArrayOfbyte) throws AnnotatedException {
    try {
      ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance(paramArrayOfbyte);
      return ASN1Primitive.fromByteArray(aSN1OctetString.getOctets());
    } catch (Exception exception) {
      throw new AnnotatedException("exception processing extension " + paramString, exception);
    } 
  }
  
  protected static AlgorithmIdentifier getAlgorithmIdentifier(PublicKey paramPublicKey) throws CertPathValidatorException {
    try {
      return SubjectPublicKeyInfo.getInstance(paramPublicKey.getEncoded()).getAlgorithm();
    } catch (Exception exception) {
      throw new ExtCertPathValidatorException("Subject public key cannot be decoded.", exception);
    } 
  }
  
  protected static final Set getQualifierSet(ASN1Sequence paramASN1Sequence) throws CertPathValidatorException {
    HashSet<PolicyQualifierInfo> hashSet = new HashSet();
    if (paramASN1Sequence == null)
      return hashSet; 
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    ASN1OutputStream aSN1OutputStream = ASN1OutputStream.create(byteArrayOutputStream);
    Enumeration<ASN1Encodable> enumeration = paramASN1Sequence.getObjects();
    while (enumeration.hasMoreElements()) {
      try {
        aSN1OutputStream.writeObject(enumeration.nextElement());
        hashSet.add(new PolicyQualifierInfo(byteArrayOutputStream.toByteArray()));
      } catch (IOException iOException) {
        throw new ExtCertPathValidatorException("Policy qualifier info cannot be decoded.", iOException);
      } 
      byteArrayOutputStream.reset();
    } 
    return hashSet;
  }
  
  protected static PKIXPolicyNode removePolicyNode(PKIXPolicyNode paramPKIXPolicyNode1, List[] paramArrayOfList, PKIXPolicyNode paramPKIXPolicyNode2) {
    PKIXPolicyNode pKIXPolicyNode = (PKIXPolicyNode)paramPKIXPolicyNode2.getParent();
    if (paramPKIXPolicyNode1 == null)
      return null; 
    if (pKIXPolicyNode == null) {
      for (byte b = 0; b < paramArrayOfList.length; b++)
        paramArrayOfList[b] = new ArrayList(); 
      return null;
    } 
    pKIXPolicyNode.removeChild(paramPKIXPolicyNode2);
    removePolicyNodeRecurse(paramArrayOfList, paramPKIXPolicyNode2);
    return paramPKIXPolicyNode1;
  }
  
  private static void removePolicyNodeRecurse(List[] paramArrayOfList, PKIXPolicyNode paramPKIXPolicyNode) {
    paramArrayOfList[paramPKIXPolicyNode.getDepth()].remove(paramPKIXPolicyNode);
    if (paramPKIXPolicyNode.hasChildren()) {
      Iterator<PKIXPolicyNode> iterator = paramPKIXPolicyNode.getChildren();
      while (iterator.hasNext()) {
        PKIXPolicyNode pKIXPolicyNode = iterator.next();
        removePolicyNodeRecurse(paramArrayOfList, pKIXPolicyNode);
      } 
    } 
  }
  
  protected static boolean processCertD1i(int paramInt, List[] paramArrayOfList, ASN1ObjectIdentifier paramASN1ObjectIdentifier, Set paramSet) {
    List<PKIXPolicyNode> list = paramArrayOfList[paramInt - 1];
    for (byte b = 0; b < list.size(); b++) {
      PKIXPolicyNode pKIXPolicyNode = list.get(b);
      Set set = pKIXPolicyNode.getExpectedPolicies();
      if (set.contains(paramASN1ObjectIdentifier.getId())) {
        HashSet<String> hashSet = new HashSet();
        hashSet.add(paramASN1ObjectIdentifier.getId());
        PKIXPolicyNode pKIXPolicyNode1 = new PKIXPolicyNode(new ArrayList(), paramInt, hashSet, pKIXPolicyNode, paramSet, paramASN1ObjectIdentifier.getId(), false);
        pKIXPolicyNode.addChild(pKIXPolicyNode1);
        paramArrayOfList[paramInt].add(pKIXPolicyNode1);
        return true;
      } 
    } 
    return false;
  }
  
  protected static void processCertD1ii(int paramInt, List[] paramArrayOfList, ASN1ObjectIdentifier paramASN1ObjectIdentifier, Set paramSet) {
    List<PKIXPolicyNode> list = paramArrayOfList[paramInt - 1];
    for (byte b = 0; b < list.size(); b++) {
      PKIXPolicyNode pKIXPolicyNode = list.get(b);
      if ("2.5.29.32.0".equals(pKIXPolicyNode.getValidPolicy())) {
        HashSet<String> hashSet = new HashSet();
        hashSet.add(paramASN1ObjectIdentifier.getId());
        PKIXPolicyNode pKIXPolicyNode1 = new PKIXPolicyNode(new ArrayList(), paramInt, hashSet, pKIXPolicyNode, paramSet, paramASN1ObjectIdentifier.getId(), false);
        pKIXPolicyNode.addChild(pKIXPolicyNode1);
        paramArrayOfList[paramInt].add(pKIXPolicyNode1);
        return;
      } 
    } 
  }
  
  protected static void prepareNextCertB1(int paramInt, List[] paramArrayOfList, String paramString, Map paramMap, X509Certificate paramX509Certificate) throws AnnotatedException, CertPathValidatorException {
    boolean bool = false;
    for (PKIXPolicyNode pKIXPolicyNode : paramArrayOfList[paramInt]) {
      if (pKIXPolicyNode.getValidPolicy().equals(paramString)) {
        bool = true;
        pKIXPolicyNode.expectedPolicies = (Set)paramMap.get(paramString);
        break;
      } 
    } 
    if (!bool)
      for (PKIXPolicyNode pKIXPolicyNode : paramArrayOfList[paramInt]) {
        if ("2.5.29.32.0".equals(pKIXPolicyNode.getValidPolicy())) {
          Set set = null;
          ASN1Sequence aSN1Sequence = null;
          try {
            aSN1Sequence = DERSequence.getInstance(getExtensionValue(paramX509Certificate, CERTIFICATE_POLICIES));
          } catch (Exception exception) {
            throw new AnnotatedException("Certificate policies cannot be decoded.", exception);
          } 
          Enumeration enumeration = aSN1Sequence.getObjects();
          while (enumeration.hasMoreElements()) {
            PolicyInformation policyInformation = null;
            try {
              policyInformation = PolicyInformation.getInstance(enumeration.nextElement());
            } catch (Exception exception) {
              throw new AnnotatedException("Policy information cannot be decoded.", exception);
            } 
            if ("2.5.29.32.0".equals(policyInformation.getPolicyIdentifier().getId())) {
              try {
                set = getQualifierSet(policyInformation.getPolicyQualifiers());
              } catch (CertPathValidatorException certPathValidatorException) {
                throw new ExtCertPathValidatorException("Policy qualifier info set could not be built.", certPathValidatorException);
              } 
              break;
            } 
          } 
          boolean bool1 = false;
          if (paramX509Certificate.getCriticalExtensionOIDs() != null)
            bool1 = paramX509Certificate.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES); 
          PKIXPolicyNode pKIXPolicyNode1 = (PKIXPolicyNode)pKIXPolicyNode.getParent();
          if ("2.5.29.32.0".equals(pKIXPolicyNode1.getValidPolicy())) {
            PKIXPolicyNode pKIXPolicyNode2 = new PKIXPolicyNode(new ArrayList(), paramInt, (Set)paramMap.get(paramString), pKIXPolicyNode1, set, paramString, bool1);
            pKIXPolicyNode1.addChild(pKIXPolicyNode2);
            paramArrayOfList[paramInt].add(pKIXPolicyNode2);
          } 
          break;
        } 
      }  
  }
  
  protected static PKIXPolicyNode prepareNextCertB2(int paramInt, List[] paramArrayOfList, String paramString, PKIXPolicyNode paramPKIXPolicyNode) {
    Iterator<?> iterator = paramArrayOfList[paramInt].iterator();
    while (iterator.hasNext()) {
      PKIXPolicyNode pKIXPolicyNode = (PKIXPolicyNode)iterator.next();
      if (pKIXPolicyNode.getValidPolicy().equals(paramString)) {
        PKIXPolicyNode pKIXPolicyNode1 = (PKIXPolicyNode)pKIXPolicyNode.getParent();
        pKIXPolicyNode1.removeChild(pKIXPolicyNode);
        iterator.remove();
        for (int i = paramInt - 1; i >= 0; i--) {
          List<PKIXPolicyNode> list = paramArrayOfList[i];
          for (byte b = 0; b < list.size(); b++) {
            PKIXPolicyNode pKIXPolicyNode2 = list.get(b);
            if (!pKIXPolicyNode2.hasChildren()) {
              paramPKIXPolicyNode = removePolicyNode(paramPKIXPolicyNode, paramArrayOfList, pKIXPolicyNode2);
              if (paramPKIXPolicyNode == null)
                break; 
            } 
          } 
        } 
      } 
    } 
    return paramPKIXPolicyNode;
  }
  
  protected static boolean isAnyPolicy(Set paramSet) {
    return (paramSet == null || paramSet.contains("2.5.29.32.0") || paramSet.isEmpty());
  }
  
  protected static void findCertificates(LinkedHashSet<Certificate> paramLinkedHashSet, PKIXCertStoreSelector paramPKIXCertStoreSelector, List paramList) throws AnnotatedException {
    for (Store store : paramList) {
      if (store instanceof Store) {
        Store store1 = store;
        try {
          paramLinkedHashSet.addAll(store1.getMatches(paramPKIXCertStoreSelector));
        } catch (StoreException storeException) {
          throw new AnnotatedException("Problem while picking certificates from X.509 store.", storeException);
        } 
        continue;
      } 
      CertStore certStore = (CertStore)store;
      try {
        paramLinkedHashSet.addAll(PKIXCertStoreSelector.getCertificates(paramPKIXCertStoreSelector, certStore));
      } catch (CertStoreException certStoreException) {
        throw new AnnotatedException("Problem while picking certificates from certificate store.", certStoreException);
      } 
    } 
  }
  
  static List<PKIXCRLStore> getAdditionalStoresFromCRLDistributionPoint(CRLDistPoint paramCRLDistPoint, Map<GeneralName, PKIXCRLStore> paramMap, Date paramDate, JcaJceHelper paramJcaJceHelper) throws AnnotatedException {
    DistributionPoint[] arrayOfDistributionPoint;
    if (null == paramCRLDistPoint)
      return Collections.EMPTY_LIST; 
    try {
      arrayOfDistributionPoint = paramCRLDistPoint.getDistributionPoints();
    } catch (Exception exception) {
      throw new AnnotatedException("Distribution points could not be read.", exception);
    } 
    ArrayList<PKIXCRLStore> arrayList = new ArrayList();
    for (byte b = 0; b < arrayOfDistributionPoint.length; b++) {
      DistributionPointName distributionPointName = arrayOfDistributionPoint[b].getDistributionPoint();
      if (distributionPointName != null && distributionPointName.getType() == 0) {
        GeneralName[] arrayOfGeneralName = GeneralNames.getInstance(distributionPointName.getName()).getNames();
        for (byte b1 = 0; b1 < arrayOfGeneralName.length; b1++) {
          PKIXCRLStore pKIXCRLStore = paramMap.get(arrayOfGeneralName[b1]);
          if (pKIXCRLStore != null)
            arrayList.add(pKIXCRLStore); 
        } 
      } 
    } 
    if (arrayList.isEmpty() && Properties.isOverrideSet("org.bouncycastle.x509.enableCRLDP")) {
      CertificateFactory certificateFactory;
      try {
        certificateFactory = paramJcaJceHelper.createCertificateFactory("X.509");
      } catch (Exception exception) {
        throw new AnnotatedException("cannot create certificate factory: " + exception.getMessage(), exception);
      } 
      for (byte b1 = 0; b1 < arrayOfDistributionPoint.length; b1++) {
        DistributionPointName distributionPointName = arrayOfDistributionPoint[b1].getDistributionPoint();
        if (distributionPointName != null && distributionPointName.getType() == 0) {
          GeneralName[] arrayOfGeneralName = GeneralNames.getInstance(distributionPointName.getName()).getNames();
          for (byte b2 = 0; b2 < arrayOfGeneralName.length; b2++) {
            GeneralName generalName = arrayOfGeneralName[b1];
            if (generalName.getTagNo() == 6)
              try {
                URI uRI = new URI(((ASN1String)generalName.getName()).getString());
                PKIXCRLStore pKIXCRLStore = CrlCache.getCrl(certificateFactory, paramDate, uRI);
                if (pKIXCRLStore != null)
                  arrayList.add(pKIXCRLStore); 
                break;
              } catch (Exception exception) {} 
          } 
        } 
      } 
    } 
    return arrayList;
  }
  
  protected static void getCRLIssuersFromDistributionPoint(DistributionPoint paramDistributionPoint, Collection paramCollection, X509CRLSelector paramX509CRLSelector) throws AnnotatedException {
    ArrayList<X500Name> arrayList = new ArrayList();
    if (paramDistributionPoint.getCRLIssuer() != null) {
      GeneralName[] arrayOfGeneralName = paramDistributionPoint.getCRLIssuer().getNames();
      for (byte b = 0; b < arrayOfGeneralName.length; b++) {
        if (arrayOfGeneralName[b].getTagNo() == 4)
          try {
            arrayList.add(X500Name.getInstance(arrayOfGeneralName[b].getName().toASN1Primitive().getEncoded()));
          } catch (IOException iOException) {
            throw new AnnotatedException("CRL issuer information from distribution point cannot be decoded.", iOException);
          }  
      } 
    } else {
      if (paramDistributionPoint.getDistributionPoint() == null)
        throw new AnnotatedException("CRL issuer is omitted from distribution point but no distributionPoint field present."); 
      Iterator<X500Name> iterator1 = paramCollection.iterator();
      while (iterator1.hasNext())
        arrayList.add(iterator1.next()); 
    } 
    Iterator<X500Name> iterator = arrayList.iterator();
    while (iterator.hasNext()) {
      try {
        paramX509CRLSelector.addIssuerName(((X500Name)iterator.next()).getEncoded());
      } catch (IOException iOException) {
        throw new AnnotatedException("Cannot decode CRL issuer information.", iOException);
      } 
    } 
  }
  
  private static BigInteger getSerialNumber(Object paramObject) {
    return ((X509Certificate)paramObject).getSerialNumber();
  }
  
  protected static void getCertStatus(Date paramDate, X509CRL paramX509CRL, Object paramObject, CertStatus paramCertStatus) throws AnnotatedException {
    boolean bool;
    X509CRLEntry x509CRLEntry;
    try {
      bool = X509CRLObject.isIndirectCRL(paramX509CRL);
    } catch (CRLException cRLException) {
      throw new AnnotatedException("Failed check for indirect CRL.", cRLException);
    } 
    if (bool) {
      X500Name x500Name;
      x509CRLEntry = paramX509CRL.getRevokedCertificate(getSerialNumber(paramObject));
      if (x509CRLEntry == null)
        return; 
      X500Principal x500Principal = x509CRLEntry.getCertificateIssuer();
      if (x500Principal == null) {
        x500Name = PrincipalUtils.getIssuerPrincipal(paramX509CRL);
      } else {
        x500Name = PrincipalUtils.getX500Name(x500Principal);
      } 
      if (!PrincipalUtils.getEncodedIssuerPrincipal(paramObject).equals(x500Name))
        return; 
    } else {
      if (!PrincipalUtils.getEncodedIssuerPrincipal(paramObject).equals(PrincipalUtils.getIssuerPrincipal(paramX509CRL)))
        return; 
      x509CRLEntry = paramX509CRL.getRevokedCertificate(getSerialNumber(paramObject));
      if (x509CRLEntry == null)
        return; 
    } 
    ASN1Enumerated aSN1Enumerated = null;
    if (x509CRLEntry.hasExtensions()) {
      if (x509CRLEntry.hasUnsupportedCriticalExtension())
        throw new AnnotatedException("CRL entry has unsupported critical extensions."); 
      try {
        aSN1Enumerated = ASN1Enumerated.getInstance(getExtensionValue(x509CRLEntry, Extension.reasonCode.getId()));
      } catch (Exception exception) {
        throw new AnnotatedException("Reason code CRL entry extension could not be decoded.", exception);
      } 
    } 
    boolean bool1 = (null == aSN1Enumerated) ? false : aSN1Enumerated.intValueExact();
    if (paramDate.getTime() >= x509CRLEntry.getRevocationDate().getTime() || !bool1 || bool1 == true || bool1 == 2 || bool1 == 10) {
      paramCertStatus.setCertStatus(bool1);
      paramCertStatus.setRevocationDate(x509CRLEntry.getRevocationDate());
    } 
  }
  
  protected static Set getDeltaCRLs(Date paramDate, X509CRL paramX509CRL, List<CertStore> paramList, List<PKIXCRLStore> paramList1, JcaJceHelper paramJcaJceHelper) throws AnnotatedException {
    byte[] arrayOfByte;
    X509CRLSelector x509CRLSelector = new X509CRLSelector();
    try {
      x509CRLSelector.addIssuerName(PrincipalUtils.getIssuerPrincipal(paramX509CRL).getEncoded());
    } catch (IOException iOException) {
      throw new AnnotatedException("Cannot extract issuer from CRL.", iOException);
    } 
    BigInteger bigInteger = null;
    try {
      ASN1Primitive aSN1Primitive = getExtensionValue(paramX509CRL, CRL_NUMBER);
      if (aSN1Primitive != null)
        bigInteger = ASN1Integer.getInstance(aSN1Primitive).getPositiveValue(); 
    } catch (Exception exception) {
      throw new AnnotatedException("CRL number extension could not be extracted from CRL.", exception);
    } 
    try {
      arrayOfByte = paramX509CRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
    } catch (Exception exception) {
      throw new AnnotatedException("Issuing distribution point extension value could not be read.", exception);
    } 
    x509CRLSelector.setMinCRLNumber((bigInteger == null) ? null : bigInteger.add(BigInteger.valueOf(1L)));
    PKIXCRLStoreSelector.Builder builder = new PKIXCRLStoreSelector.Builder(x509CRLSelector);
    builder.setIssuingDistributionPoint(arrayOfByte);
    builder.setIssuingDistributionPointEnabled(true);
    builder.setMaxBaseCRLNumber(bigInteger);
    PKIXCRLStoreSelector<? extends CRL> pKIXCRLStoreSelector = builder.build();
    Set set = PKIXCRLUtil.findCRLs(pKIXCRLStoreSelector, paramDate, paramList, paramList1);
    if (set.isEmpty() && Properties.isOverrideSet("org.bouncycastle.x509.enableCRLDP")) {
      CertificateFactory certificateFactory;
      try {
        certificateFactory = paramJcaJceHelper.createCertificateFactory("X.509");
      } catch (Exception exception) {
        throw new AnnotatedException("cannot create certificate factory: " + exception.getMessage(), exception);
      } 
      CRLDistPoint cRLDistPoint = CRLDistPoint.getInstance(arrayOfByte);
      DistributionPoint[] arrayOfDistributionPoint = cRLDistPoint.getDistributionPoints();
      for (byte b = 0; b < arrayOfDistributionPoint.length; b++) {
        DistributionPointName distributionPointName = arrayOfDistributionPoint[b].getDistributionPoint();
        if (distributionPointName != null && distributionPointName.getType() == 0) {
          GeneralName[] arrayOfGeneralName = GeneralNames.getInstance(distributionPointName.getName()).getNames();
          for (byte b1 = 0; b1 < arrayOfGeneralName.length; b1++) {
            GeneralName generalName = arrayOfGeneralName[b];
            if (generalName.getTagNo() == 6)
              try {
                PKIXCRLStore pKIXCRLStore = CrlCache.getCrl(certificateFactory, paramDate, new URI(((ASN1String)generalName.getName()).getString()));
                if (pKIXCRLStore != null)
                  set = PKIXCRLUtil.findCRLs(pKIXCRLStoreSelector, paramDate, Collections.EMPTY_LIST, Collections.singletonList(pKIXCRLStore)); 
                break;
              } catch (Exception exception) {} 
          } 
        } 
      } 
    } 
    HashSet<X509CRL> hashSet = new HashSet();
    for (X509CRL x509CRL : set) {
      if (isDeltaCRL(x509CRL))
        hashSet.add(x509CRL); 
    } 
    return hashSet;
  }
  
  private static boolean isDeltaCRL(X509CRL paramX509CRL) {
    Set<String> set = paramX509CRL.getCriticalExtensionOIDs();
    return (set == null) ? false : set.contains(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
  }
  
  protected static Set getCompleteCRLs(PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters, DistributionPoint paramDistributionPoint, Object paramObject, PKIXExtendedParameters paramPKIXExtendedParameters, Date paramDate) throws AnnotatedException, RecoverableCertPathValidatorException {
    X509CRLSelector x509CRLSelector = new X509CRLSelector();
    try {
      HashSet<X500Name> hashSet = new HashSet();
      hashSet.add(PrincipalUtils.getEncodedIssuerPrincipal(paramObject));
      getCRLIssuersFromDistributionPoint(paramDistributionPoint, hashSet, x509CRLSelector);
    } catch (AnnotatedException annotatedException) {
      throw new AnnotatedException("Could not get issuer information from distribution point.", annotatedException);
    } 
    if (paramObject instanceof X509Certificate)
      x509CRLSelector.setCertificateChecking((X509Certificate)paramObject); 
    PKIXCRLStoreSelector<? extends CRL> pKIXCRLStoreSelector = (new PKIXCRLStoreSelector.Builder(x509CRLSelector)).setCompleteCRLEnabled(true).build();
    Set set = PKIXCRLUtil.findCRLs(pKIXCRLStoreSelector, paramDate, paramPKIXExtendedParameters.getCertStores(), paramPKIXExtendedParameters.getCRLStores());
    checkCRLsNotEmpty(paramPKIXCertRevocationCheckerParameters, set, paramObject);
    return set;
  }
  
  protected static Date getValidCertDateFromValidityModel(Date paramDate, int paramInt1, CertPath paramCertPath, int paramInt2) throws AnnotatedException {
    if (1 != paramInt1 || paramInt2 <= 0)
      return paramDate; 
    X509Certificate x509Certificate = (X509Certificate)paramCertPath.getCertificates().get(paramInt2 - 1);
    if (paramInt2 - 1 == 0) {
      ASN1GeneralizedTime aSN1GeneralizedTime = null;
      try {
        byte[] arrayOfByte = ((X509Certificate)paramCertPath.getCertificates().get(paramInt2 - 1)).getExtensionValue(ISISMTTObjectIdentifiers.id_isismtt_at_dateOfCertGen.getId());
        if (arrayOfByte != null)
          aSN1GeneralizedTime = ASN1GeneralizedTime.getInstance(ASN1Primitive.fromByteArray(arrayOfByte)); 
      } catch (IOException iOException) {
        throw new AnnotatedException("Date of cert gen extension could not be read.");
      } catch (IllegalArgumentException illegalArgumentException) {
        throw new AnnotatedException("Date of cert gen extension could not be read.");
      } 
      if (aSN1GeneralizedTime != null)
        try {
          return aSN1GeneralizedTime.getDate();
        } catch (ParseException parseException) {
          throw new AnnotatedException("Date from date of cert gen extension could not be parsed.", parseException);
        }  
    } 
    return x509Certificate.getNotBefore();
  }
  
  protected static PublicKey getNextWorkingKey(List<Certificate> paramList, int paramInt, JcaJceHelper paramJcaJceHelper) throws CertPathValidatorException {
    Certificate certificate = paramList.get(paramInt);
    PublicKey publicKey = certificate.getPublicKey();
    if (!(publicKey instanceof DSAPublicKey))
      return publicKey; 
    DSAPublicKey dSAPublicKey = (DSAPublicKey)publicKey;
    if (dSAPublicKey.getParams() != null)
      return dSAPublicKey; 
    int i = paramInt + 1;
    while (i < paramList.size()) {
      X509Certificate x509Certificate = (X509Certificate)paramList.get(i);
      publicKey = x509Certificate.getPublicKey();
      if (!(publicKey instanceof DSAPublicKey))
        throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate."); 
      DSAPublicKey dSAPublicKey1 = (DSAPublicKey)publicKey;
      if (dSAPublicKey1.getParams() == null) {
        i++;
        continue;
      } 
      DSAParams dSAParams = dSAPublicKey1.getParams();
      DSAPublicKeySpec dSAPublicKeySpec = new DSAPublicKeySpec(dSAPublicKey.getY(), dSAParams.getP(), dSAParams.getQ(), dSAParams.getG());
      try {
        KeyFactory keyFactory = paramJcaJceHelper.createKeyFactory("DSA");
        return keyFactory.generatePublic(dSAPublicKeySpec);
      } catch (Exception exception) {
        throw new RuntimeException(exception.getMessage());
      } 
    } 
    throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
  }
  
  static Collection findIssuerCerts(X509Certificate paramX509Certificate, List<CertStore> paramList, List<PKIXCertStore> paramList1) throws AnnotatedException {
    X509CertSelector x509CertSelector = new X509CertSelector();
    try {
      x509CertSelector.setSubject(PrincipalUtils.getIssuerPrincipal(paramX509Certificate).getEncoded());
    } catch (Exception exception) {
      throw new AnnotatedException("Subject criteria for certificate selector to find issuer certificate could not be set.", exception);
    } 
    try {
      byte[] arrayOfByte = paramX509Certificate.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
      if (arrayOfByte != null) {
        ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance(arrayOfByte);
        byte[] arrayOfByte1 = AuthorityKeyIdentifier.getInstance(aSN1OctetString.getOctets()).getKeyIdentifier();
        if (arrayOfByte1 != null)
          x509CertSelector.setSubjectKeyIdentifier((new DEROctetString(arrayOfByte1)).getEncoded()); 
      } 
    } catch (Exception exception) {}
    PKIXCertStoreSelector<? extends Certificate> pKIXCertStoreSelector = (new PKIXCertStoreSelector.Builder(x509CertSelector)).build();
    LinkedHashSet linkedHashSet = new LinkedHashSet();
    try {
      findCertificates(linkedHashSet, pKIXCertStoreSelector, paramList);
      findCertificates(linkedHashSet, pKIXCertStoreSelector, paramList1);
    } catch (AnnotatedException annotatedException) {
      throw new AnnotatedException("Issuer certificate cannot be searched.", annotatedException);
    } 
    return linkedHashSet;
  }
  
  protected static void verifyX509Certificate(X509Certificate paramX509Certificate, PublicKey paramPublicKey, String paramString) throws GeneralSecurityException {
    if (paramString == null) {
      paramX509Certificate.verify(paramPublicKey);
    } else {
      paramX509Certificate.verify(paramPublicKey, paramString);
    } 
  }
  
  static void checkCRLsNotEmpty(PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters, Set paramSet, Object paramObject) throws RecoverableCertPathValidatorException {
    if (paramSet.isEmpty()) {
      if (paramObject instanceof X509AttributeCertificate) {
        X509AttributeCertificate x509AttributeCertificate = (X509AttributeCertificate)paramObject;
        throw new RecoverableCertPathValidatorException("No CRLs found for issuer \"" + x509AttributeCertificate.getIssuer().getPrincipals()[0] + "\"", null, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex());
      } 
      X509Certificate x509Certificate = (X509Certificate)paramObject;
      throw new RecoverableCertPathValidatorException("No CRLs found for issuer \"" + RFC4519Style.INSTANCE.toString(PrincipalUtils.getIssuerPrincipal(x509Certificate)) + "\"", null, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex());
    } 
  }
}
