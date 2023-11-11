package org.bouncycastle.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.internal.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.internal.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;

class ProvRevocationChecker extends PKIXRevocationChecker implements PKIXCertRevocationChecker {
  private static final int DEFAULT_OCSP_TIMEOUT = 15000;
  
  private static final int DEFAULT_OCSP_MAX_RESPONSE_SIZE = 32768;
  
  private static final Map oids = new HashMap<Object, Object>();
  
  private final JcaJceHelper helper;
  
  private final ProvCrlRevocationChecker crlChecker;
  
  private final ProvOcspRevocationChecker ocspChecker;
  
  private PKIXCertRevocationCheckerParameters parameters;
  
  public ProvRevocationChecker(JcaJceHelper paramJcaJceHelper) {
    this.helper = paramJcaJceHelper;
    this.crlChecker = new ProvCrlRevocationChecker(paramJcaJceHelper);
    this.ocspChecker = new ProvOcspRevocationChecker(this, paramJcaJceHelper);
  }
  
  public void setParameter(String paramString, Object paramObject) {}
  
  public void initialize(PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters) {
    this.parameters = paramPKIXCertRevocationCheckerParameters;
    this.crlChecker.initialize(paramPKIXCertRevocationCheckerParameters);
    this.ocspChecker.initialize(paramPKIXCertRevocationCheckerParameters);
  }
  
  public List<CertPathValidatorException> getSoftFailExceptions() {
    return this.ocspChecker.getSoftFailExceptions();
  }
  
  public void init(boolean paramBoolean) throws CertPathValidatorException {
    this.parameters = null;
    this.crlChecker.init(paramBoolean);
    this.ocspChecker.init(paramBoolean);
  }
  
  public boolean isForwardCheckingSupported() {
    return false;
  }
  
  public Set<String> getSupportedExtensions() {
    return null;
  }
  
  public void check(Certificate paramCertificate, Collection<String> paramCollection) throws CertPathValidatorException {
    X509Certificate x509Certificate = (X509Certificate)paramCertificate;
    if (hasOption(PKIXRevocationChecker.Option.ONLY_END_ENTITY) && x509Certificate.getBasicConstraints() != -1)
      return; 
    if (hasOption(PKIXRevocationChecker.Option.PREFER_CRLS)) {
      try {
        this.crlChecker.check(paramCertificate);
      } catch (RecoverableCertPathValidatorException recoverableCertPathValidatorException) {
        if (!hasOption(PKIXRevocationChecker.Option.NO_FALLBACK)) {
          this.ocspChecker.check(paramCertificate);
        } else {
          throw recoverableCertPathValidatorException;
        } 
      } 
    } else {
      try {
        this.ocspChecker.check(paramCertificate);
      } catch (RecoverableCertPathValidatorException recoverableCertPathValidatorException) {
        if (!hasOption(PKIXRevocationChecker.Option.NO_FALLBACK)) {
          this.crlChecker.check(paramCertificate);
        } else {
          throw recoverableCertPathValidatorException;
        } 
      } 
    } 
  }
  
  private boolean hasOption(PKIXRevocationChecker.Option paramOption) {
    return getOptions().contains(paramOption);
  }
  
  static {
    oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
    oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
    oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
    oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
    oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
    oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
    oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
    oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
    oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
    oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
    oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
    oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
    oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
    oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
    oids.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
    oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
    oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
    oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
    oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
    oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
    oids.put(IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
    oids.put(IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");
    oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
    oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
    oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
    oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
    oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
    oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
    oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
    oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
    oids.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
    oids.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
    oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
    oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");
  }
}
