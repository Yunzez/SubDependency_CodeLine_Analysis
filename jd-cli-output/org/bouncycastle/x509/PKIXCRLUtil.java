package org.bouncycastle.x509;

import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.PKIXParameters;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.jce.provider.AnnotatedException;
import org.bouncycastle.util.StoreException;

abstract class PKIXCRLUtil {
  static Set findCRLs(X509CRLStoreSelector paramX509CRLStoreSelector, PKIXParameters paramPKIXParameters) throws AnnotatedException {
    HashSet hashSet = new HashSet();
    try {
      findCRLs(hashSet, paramX509CRLStoreSelector, paramPKIXParameters.getCertStores());
    } catch (AnnotatedException annotatedException) {
      throw new AnnotatedException("Exception obtaining complete CRLs.", annotatedException);
    } 
    return hashSet;
  }
  
  private static void findCRLs(HashSet<CRL> paramHashSet, X509CRLStoreSelector paramX509CRLStoreSelector, List paramList) throws AnnotatedException {
    AnnotatedException annotatedException = null;
    boolean bool = false;
    for (X509Store x509Store : paramList) {
      if (x509Store instanceof X509Store) {
        X509Store x509Store1 = x509Store;
        try {
          paramHashSet.addAll(x509Store1.getMatches(paramX509CRLStoreSelector));
          bool = true;
        } catch (StoreException storeException) {
          annotatedException = new AnnotatedException("Exception searching in X.509 CRL store.", storeException);
        } 
        continue;
      } 
      CertStore certStore = (CertStore)x509Store;
      try {
        paramHashSet.addAll(certStore.getCRLs(paramX509CRLStoreSelector));
        bool = true;
      } catch (CertStoreException certStoreException) {
        annotatedException = new AnnotatedException("Exception searching in X.509 CRL store.", certStoreException);
      } 
    } 
    if (!bool && annotatedException != null)
      throw annotatedException; 
  }
}
