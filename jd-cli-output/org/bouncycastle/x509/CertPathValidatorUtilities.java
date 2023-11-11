package org.bouncycastle.x509;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.PKIXParameters;
import java.security.cert.PolicyQualifierInfo;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.cert.X509Extension;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.jcajce.PKIXCertStoreSelector;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.jce.provider.PKIXPolicyNode;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

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
  
  protected static final String CRL_NUMBER = Extension.cRLNumber.getId();
  
  protected static final String ANY_POLICY = "2.5.29.32.0";
  
  protected static final int KEY_CERT_SIGN = 5;
  
  protected static final int CRL_SIGN = 6;
  
  protected static final String[] crlReasons = new String[] { 
      "unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", 
      "aACompromise" };
  
  protected static X500Principal getEncodedIssuerPrincipal(Object paramObject) {
    return (paramObject instanceof X509Certificate) ? ((X509Certificate)paramObject).getIssuerX500Principal() : (X500Principal)((X509AttributeCertificate)paramObject).getIssuer().getPrincipals()[0];
  }
  
  protected static Date getValidityDate(PKIXParameters paramPKIXParameters, Date paramDate) {
    Date date = paramPKIXParameters.getDate();
    return (null == date) ? paramDate : date;
  }
  
  protected static X500Principal getSubjectPrincipal(X509Certificate paramX509Certificate) {
    return paramX509Certificate.getSubjectX500Principal();
  }
  
  protected static boolean isSelfIssued(X509Certificate paramX509Certificate) {
    return paramX509Certificate.getSubjectDN().equals(paramX509Certificate.getIssuerDN());
  }
  
  protected static ASN1Primitive getExtensionValue(X509Extension paramX509Extension, String paramString) throws AnnotatedException {
    byte[] arrayOfByte = paramX509Extension.getExtensionValue(paramString);
    return (arrayOfByte == null) ? null : getObject(paramString, arrayOfByte);
  }
  
  private static ASN1Primitive getObject(String paramString, byte[] paramArrayOfbyte) throws AnnotatedException {
    try {
      ASN1InputStream aSN1InputStream = new ASN1InputStream(paramArrayOfbyte);
      ASN1OctetString aSN1OctetString = (ASN1OctetString)aSN1InputStream.readObject();
      aSN1InputStream = new ASN1InputStream(aSN1OctetString.getOctets());
      return aSN1InputStream.readObject();
    } catch (Exception exception) {
      throw new AnnotatedException("exception processing extension " + paramString, exception);
    } 
  }
  
  protected static X500Principal getIssuerPrincipal(X509CRL paramX509CRL) {
    return paramX509CRL.getIssuerX500Principal();
  }
  
  protected static AlgorithmIdentifier getAlgorithmIdentifier(PublicKey paramPublicKey) throws CertPathValidatorException {
    try {
      ASN1InputStream aSN1InputStream = new ASN1InputStream(paramPublicKey.getEncoded());
      SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(aSN1InputStream.readObject());
      return subjectPublicKeyInfo.getAlgorithmId();
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
        pKIXPolicyNode.setExpectedPolicies((Set)paramMap.get(paramString));
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
  
  protected static Collection findCertificates(X509CertStoreSelector paramX509CertStoreSelector, List paramList) throws AnnotatedException {
    HashSet<Certificate> hashSet = new HashSet();
    Iterator<Object> iterator = paramList.iterator();
    CertificateFactory certificateFactory = new CertificateFactory();
    while (iterator.hasNext()) {
      Store store = (Store)iterator.next();
      if (store instanceof Store) {
        Store store1 = store;
        try {
          for (Encodable encodable : store1.getMatches(paramX509CertStoreSelector)) {
            if (encodable instanceof Encodable) {
              hashSet.add(certificateFactory.engineGenerateCertificate(new ByteArrayInputStream(((Encodable)encodable).getEncoded())));
              continue;
            } 
            if (encodable instanceof Certificate) {
              hashSet.add(encodable);
              continue;
            } 
            throw new AnnotatedException("Unknown object found in certificate store.");
          } 
        } catch (StoreException storeException) {
          throw new AnnotatedException("Problem while picking certificates from X.509 store.", storeException);
        } catch (IOException iOException) {
          throw new AnnotatedException("Problem while extracting certificates from X.509 store.", iOException);
        } catch (CertificateException certificateException) {
          throw new AnnotatedException("Problem while extracting certificates from X.509 store.", certificateException);
        } 
        continue;
      } 
      CertStore certStore = (CertStore)store;
      try {
        hashSet.addAll(certStore.getCertificates(paramX509CertStoreSelector));
      } catch (CertStoreException certStoreException) {
        throw new AnnotatedException("Problem while picking certificates from certificate store.", certStoreException);
      } 
    } 
    return hashSet;
  }
  
  protected static Collection findCertificates(PKIXCertStoreSelector paramPKIXCertStoreSelector, List paramList) throws AnnotatedException {
    HashSet<Certificate> hashSet = new HashSet();
    for (Store store : paramList) {
      if (store instanceof Store) {
        Store store1 = store;
        try {
          hashSet.addAll(store1.getMatches(paramPKIXCertStoreSelector));
        } catch (StoreException storeException) {
          throw new AnnotatedException("Problem while picking certificates from X.509 store.", storeException);
        } 
        continue;
      } 
      CertStore certStore = (CertStore)store;
      try {
        hashSet.addAll(PKIXCertStoreSelector.getCertificates(paramPKIXCertStoreSelector, certStore));
      } catch (CertStoreException certStoreException) {
        throw new AnnotatedException("Problem while picking certificates from certificate store.", certStoreException);
      } 
    } 
    return hashSet;
  }
  
  protected static Collection findCertificates(X509AttributeCertStoreSelector paramX509AttributeCertStoreSelector, List paramList) throws AnnotatedException {
    HashSet hashSet = new HashSet();
    for (X509Store x509Store : paramList) {
      if (x509Store instanceof X509Store) {
        X509Store x509Store1 = x509Store;
        try {
          hashSet.addAll(x509Store1.getMatches(paramX509AttributeCertStoreSelector));
        } catch (StoreException storeException) {
          throw new AnnotatedException("Problem while picking certificates from X.509 store.", storeException);
        } 
      } 
    } 
    return hashSet;
  }
  
  private static BigInteger getSerialNumber(Object paramObject) {
    return (paramObject instanceof X509Certificate) ? ((X509Certificate)paramObject).getSerialNumber() : ((X509AttributeCertificate)paramObject).getSerialNumber();
  }
  
  protected static void getCertStatus(Date paramDate, X509CRL paramX509CRL, Object paramObject, CertStatus paramCertStatus) throws AnnotatedException {
    boolean bool;
    X509CRLEntry x509CRLEntry = null;
    try {
      bool = isIndirectCRL(paramX509CRL);
    } catch (CRLException cRLException) {
      throw new AnnotatedException("Failed check for indirect CRL.", cRLException);
    } 
    if (bool) {
      x509CRLEntry = paramX509CRL.getRevokedCertificate(getSerialNumber(paramObject));
      if (x509CRLEntry == null)
        return; 
      X500Principal x500Principal = x509CRLEntry.getCertificateIssuer();
      if (x500Principal == null)
        x500Principal = getIssuerPrincipal(paramX509CRL); 
      if (!getEncodedIssuerPrincipal(paramObject).equals(x500Principal))
        return; 
    } else {
      if (!getEncodedIssuerPrincipal(paramObject).equals(getIssuerPrincipal(paramX509CRL)))
        return; 
      x509CRLEntry = paramX509CRL.getRevokedCertificate(getSerialNumber(paramObject));
      if (x509CRLEntry == null)
        return; 
    } 
    ASN1Enumerated aSN1Enumerated = null;
    if (x509CRLEntry.hasExtensions())
      try {
        aSN1Enumerated = ASN1Enumerated.getInstance(getExtensionValue(x509CRLEntry, X509Extension.reasonCode.getId()));
      } catch (Exception exception) {
        throw new AnnotatedException("Reason code CRL entry extension could not be decoded.", exception);
      }  
    boolean bool1 = (null == aSN1Enumerated) ? false : aSN1Enumerated.intValueExact();
    if (paramDate.getTime() >= x509CRLEntry.getRevocationDate().getTime() || !bool1 || bool1 == true || bool1 == 2 || bool1 == 10) {
      paramCertStatus.setCertStatus(bool1);
      paramCertStatus.setRevocationDate(x509CRLEntry.getRevocationDate());
    } 
  }
  
  protected static PublicKey getNextWorkingKey(List<Certificate> paramList, int paramInt) throws CertPathValidatorException {
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
        KeyFactory keyFactory = KeyFactory.getInstance("DSA", "BC");
        return keyFactory.generatePublic(dSAPublicKeySpec);
      } catch (Exception exception) {
        throw new RuntimeException(exception.getMessage());
      } 
    } 
    throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
  }
  
  protected static void verifyX509Certificate(X509Certificate paramX509Certificate, PublicKey paramPublicKey, String paramString) throws GeneralSecurityException {
    if (paramString == null) {
      paramX509Certificate.verify(paramPublicKey);
    } else {
      paramX509Certificate.verify(paramPublicKey, paramString);
    } 
  }
  
  static boolean isIndirectCRL(X509CRL paramX509CRL) throws CRLException {
    try {
      byte[] arrayOfByte = paramX509CRL.getExtensionValue(Extension.issuingDistributionPoint.getId());
      return (arrayOfByte != null && IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(arrayOfByte).getOctets()).isIndirectCRL());
    } catch (Exception exception) {
      throw new CRLException("Exception reading IssuingDistributionPoint: " + exception);
    } 
  }
}
