package org.bouncycastle.jce.provider;

import java.security.cert.CRL;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.bouncycastle.jcajce.PKIXCRLStoreSelector;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.StoreException;

abstract class PKIXCRLUtil {
  static Set findCRLs(PKIXCRLStoreSelector paramPKIXCRLStoreSelector, Date paramDate, List paramList1, List paramList2) throws AnnotatedException {
    HashSet hashSet = new HashSet();
    try {
      findCRLs(hashSet, paramPKIXCRLStoreSelector, paramList2);
      findCRLs(hashSet, paramPKIXCRLStoreSelector, paramList1);
    } catch (AnnotatedException annotatedException) {
      throw new AnnotatedException("Exception obtaining complete CRLs.", annotatedException);
    } 
    HashSet<X509CRL> hashSet1 = new HashSet();
    for (X509CRL x509CRL : hashSet) {
      Date date = x509CRL.getNextUpdate();
      if (date == null || date.after(paramDate)) {
        X509Certificate x509Certificate = paramPKIXCRLStoreSelector.getCertificateChecking();
        if (null == x509Certificate || x509CRL.getThisUpdate().before(x509Certificate.getNotAfter()))
          hashSet1.add(x509CRL); 
      } 
    } 
    return hashSet1;
  }
  
  private static void findCRLs(HashSet<CRL> paramHashSet, PKIXCRLStoreSelector paramPKIXCRLStoreSelector, List paramList) throws AnnotatedException {
    AnnotatedException annotatedException = null;
    boolean bool = false;
    for (Store store : paramList) {
      if (store instanceof Store) {
        Store store1 = store;
        try {
          paramHashSet.addAll(store1.getMatches(paramPKIXCRLStoreSelector));
          bool = true;
        } catch (StoreException storeException) {
          annotatedException = new AnnotatedException("Exception searching in X.509 CRL store.", storeException);
        } 
        continue;
      } 
      CertStore certStore = (CertStore)store;
      try {
        paramHashSet.addAll(PKIXCRLStoreSelector.getCRLs(paramPKIXCRLStoreSelector, certStore));
        bool = true;
      } catch (CertStoreException certStoreException) {
        annotatedException = new AnnotatedException("Exception searching in X.509 CRL store.", certStoreException);
      } 
    } 
    if (!bool && annotatedException != null)
      throw annotatedException; 
  }
}
