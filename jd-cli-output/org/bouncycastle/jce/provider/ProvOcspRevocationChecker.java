package org.bouncycastle.jce.provider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.RevokedInfo;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStrictStyle;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.internal.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.internal.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.exception.ExtCertPathValidatorException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

class ProvOcspRevocationChecker implements PKIXCertRevocationChecker {
  private static final int DEFAULT_OCSP_TIMEOUT = 15000;
  
  private static final int DEFAULT_OCSP_MAX_RESPONSE_SIZE = 32768;
  
  private static final Map oids = new HashMap<Object, Object>();
  
  private final ProvRevocationChecker parent;
  
  private final JcaJceHelper helper;
  
  private PKIXCertRevocationCheckerParameters parameters;
  
  private boolean isEnabledOCSP;
  
  private String ocspURL;
  
  public ProvOcspRevocationChecker(ProvRevocationChecker paramProvRevocationChecker, JcaJceHelper paramJcaJceHelper) {
    this.parent = paramProvRevocationChecker;
    this.helper = paramJcaJceHelper;
  }
  
  public void setParameter(String paramString, Object paramObject) {}
  
  public void initialize(PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters) {
    this.parameters = paramPKIXCertRevocationCheckerParameters;
    this.isEnabledOCSP = Properties.isOverrideSet("ocsp.enable");
    this.ocspURL = Properties.getPropertyValue("ocsp.responderURL");
  }
  
  public List<CertPathValidatorException> getSoftFailExceptions() {
    return null;
  }
  
  public void init(boolean paramBoolean) throws CertPathValidatorException {
    if (paramBoolean)
      throw new CertPathValidatorException("forward checking not supported"); 
    this.parameters = null;
    this.isEnabledOCSP = Properties.isOverrideSet("ocsp.enable");
    this.ocspURL = Properties.getPropertyValue("ocsp.responderURL");
  }
  
  public boolean isForwardCheckingSupported() {
    return false;
  }
  
  public Set<String> getSupportedExtensions() {
    return null;
  }
  
  public void check(Certificate paramCertificate) throws CertPathValidatorException {
    X509Certificate x509Certificate = (X509Certificate)paramCertificate;
    Map<X509Certificate, byte[]> map = this.parent.getOcspResponses();
    URI uRI = this.parent.getOcspResponder();
    if (uRI == null)
      if (this.ocspURL != null) {
        try {
          uRI = new URI(this.ocspURL);
        } catch (URISyntaxException uRISyntaxException) {
          throw new CertPathValidatorException("configuration error: " + uRISyntaxException.getMessage(), uRISyntaxException, this.parameters.getCertPath(), this.parameters.getIndex());
        } 
      } else {
        uRI = getOcspResponderURI(x509Certificate);
      }  
    byte[] arrayOfByte = null;
    boolean bool = false;
    if (map.get(x509Certificate) == null && uRI != null) {
      if (this.ocspURL == null && this.parent.getOcspResponder() == null && !this.isEnabledOCSP)
        throw new RecoverableCertPathValidatorException("OCSP disabled by \"ocsp.enable\" setting", null, this.parameters.getCertPath(), this.parameters.getIndex()); 
      Certificate certificate = extractCert();
      CertID certID = createCertID(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1), certificate, new ASN1Integer(x509Certificate.getSerialNumber()));
      OCSPResponse oCSPResponse = OcspCache.getOcspResponse(certID, this.parameters, uRI, this.parent.getOcspResponderCert(), this.parent.getOcspExtensions(), this.helper);
      try {
        map.put(x509Certificate, oCSPResponse.getEncoded());
        bool = true;
      } catch (IOException iOException) {
        throw new CertPathValidatorException("unable to encode OCSP response", iOException, this.parameters.getCertPath(), this.parameters.getIndex());
      } 
    } else {
      List<Extension> list = this.parent.getOcspExtensions();
      for (byte b = 0; b != list.size(); b++) {
        Extension extension = list.get(b);
        byte[] arrayOfByte1 = extension.getValue();
        if (OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId().equals(extension.getId()))
          arrayOfByte = arrayOfByte1; 
      } 
    } 
    if (!map.isEmpty()) {
      OCSPResponse oCSPResponse = OCSPResponse.getInstance(map.get(x509Certificate));
      ASN1Integer aSN1Integer = new ASN1Integer(x509Certificate.getSerialNumber());
      if (oCSPResponse != null) {
        if (0 == oCSPResponse.getResponseStatus().getIntValue()) {
          ResponseBytes responseBytes = ResponseBytes.getInstance(oCSPResponse.getResponseBytes());
          if (responseBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic))
            try {
              BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
              if (bool || validatedOcspResponse(basicOCSPResponse, this.parameters, arrayOfByte, this.parent.getOcspResponderCert(), this.helper)) {
                ResponseData responseData = ResponseData.getInstance(basicOCSPResponse.getTbsResponseData());
                ASN1Sequence aSN1Sequence = responseData.getResponses();
                CertID certID = null;
                for (byte b = 0; b != aSN1Sequence.size(); b++) {
                  SingleResponse singleResponse = SingleResponse.getInstance(aSN1Sequence.getObjectAt(b));
                  if (aSN1Integer.equals(singleResponse.getCertID().getSerialNumber())) {
                    ASN1GeneralizedTime aSN1GeneralizedTime = singleResponse.getNextUpdate();
                    if (aSN1GeneralizedTime != null && this.parameters.getValidDate().after(aSN1GeneralizedTime.getDate()))
                      throw new ExtCertPathValidatorException("OCSP response expired"); 
                    if (certID == null || !certID.getHashAlgorithm().equals(singleResponse.getCertID().getHashAlgorithm())) {
                      Certificate certificate = extractCert();
                      certID = createCertID(singleResponse.getCertID(), certificate, aSN1Integer);
                    } 
                    if (certID.equals(singleResponse.getCertID())) {
                      if (singleResponse.getCertStatus().getTagNo() == 0)
                        return; 
                      if (singleResponse.getCertStatus().getTagNo() == 1) {
                        RevokedInfo revokedInfo = RevokedInfo.getInstance(singleResponse.getCertStatus().getStatus());
                        CRLReason cRLReason = revokedInfo.getRevocationReason();
                        throw new CertPathValidatorException("certificate revoked, reason=(" + cRLReason + "), date=" + revokedInfo.getRevocationTime().getDate(), null, this.parameters.getCertPath(), this.parameters.getIndex());
                      } 
                      throw new CertPathValidatorException("certificate revoked, details unknown", null, this.parameters.getCertPath(), this.parameters.getIndex());
                    } 
                  } 
                } 
              } 
            } catch (CertPathValidatorException certPathValidatorException) {
              throw certPathValidatorException;
            } catch (Exception exception) {
              throw new CertPathValidatorException("unable to process OCSP response", exception, this.parameters.getCertPath(), this.parameters.getIndex());
            }  
        } else {
          throw new CertPathValidatorException("OCSP response failed: " + oCSPResponse.getResponseStatus().getValue(), null, this.parameters.getCertPath(), this.parameters.getIndex());
        } 
      } else {
        throw new RecoverableCertPathValidatorException("no OCSP response found for certificate", null, this.parameters.getCertPath(), this.parameters.getIndex());
      } 
    } else {
      throw new RecoverableCertPathValidatorException("no OCSP response found for any certificate", null, this.parameters.getCertPath(), this.parameters.getIndex());
    } 
  }
  
  static URI getOcspResponderURI(X509Certificate paramX509Certificate) {
    byte[] arrayOfByte = paramX509Certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
    if (arrayOfByte == null)
      return null; 
    AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(arrayOfByte).getOctets());
    AccessDescription[] arrayOfAccessDescription = authorityInformationAccess.getAccessDescriptions();
    for (byte b = 0; b != arrayOfAccessDescription.length; b++) {
      AccessDescription accessDescription = arrayOfAccessDescription[b];
      if (AccessDescription.id_ad_ocsp.equals(accessDescription.getAccessMethod())) {
        GeneralName generalName = accessDescription.getAccessLocation();
        if (generalName.getTagNo() == 6)
          try {
            return new URI(((ASN1String)generalName.getName()).getString());
          } catch (URISyntaxException uRISyntaxException) {} 
      } 
    } 
    return null;
  }
  
  static boolean validatedOcspResponse(BasicOCSPResponse paramBasicOCSPResponse, PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters, byte[] paramArrayOfbyte, X509Certificate paramX509Certificate, JcaJceHelper paramJcaJceHelper) throws CertPathValidatorException {
    try {
      ASN1Sequence aSN1Sequence = paramBasicOCSPResponse.getCerts();
      Signature signature = paramJcaJceHelper.createSignature(getSignatureName(paramBasicOCSPResponse.getSignatureAlgorithm()));
      X509Certificate x509Certificate = getSignerCert(paramBasicOCSPResponse, paramPKIXCertRevocationCheckerParameters.getSigningCert(), paramX509Certificate, paramJcaJceHelper);
      if (x509Certificate == null && aSN1Sequence == null)
        throw new CertPathValidatorException("OCSP responder certificate not found"); 
      if (x509Certificate != null) {
        signature.initVerify(x509Certificate.getPublicKey());
      } else {
        CertificateFactory certificateFactory = paramJcaJceHelper.createCertificateFactory("X.509");
        X509Certificate x509Certificate1 = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(aSN1Sequence.getObjectAt(0).toASN1Primitive().getEncoded()));
        x509Certificate1.verify(paramPKIXCertRevocationCheckerParameters.getSigningCert().getPublicKey());
        x509Certificate1.checkValidity(paramPKIXCertRevocationCheckerParameters.getValidDate());
        if (!responderMatches(paramBasicOCSPResponse.getTbsResponseData().getResponderID(), x509Certificate1, paramJcaJceHelper))
          throw new CertPathValidatorException("responder certificate does not match responderID", null, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex()); 
        List<String> list = x509Certificate1.getExtendedKeyUsage();
        if (list == null || !list.contains(KeyPurposeId.id_kp_OCSPSigning.getId()))
          throw new CertPathValidatorException("responder certificate not valid for signing OCSP responses", null, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex()); 
        signature.initVerify(x509Certificate1);
      } 
      signature.update(paramBasicOCSPResponse.getTbsResponseData().getEncoded("DER"));
      if (signature.verify(paramBasicOCSPResponse.getSignature().getBytes())) {
        if (paramArrayOfbyte != null) {
          Extensions extensions = paramBasicOCSPResponse.getTbsResponseData().getResponseExtensions();
          Extension extension = extensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
          if (!Arrays.areEqual(paramArrayOfbyte, extension.getExtnValue().getOctets()))
            throw new CertPathValidatorException("nonce mismatch in OCSP response", null, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex()); 
        } 
        return true;
      } 
      return false;
    } catch (CertPathValidatorException certPathValidatorException) {
      throw certPathValidatorException;
    } catch (GeneralSecurityException generalSecurityException) {
      throw new CertPathValidatorException("OCSP response failure: " + generalSecurityException.getMessage(), generalSecurityException, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex());
    } catch (IOException iOException) {
      throw new CertPathValidatorException("OCSP response failure: " + iOException.getMessage(), iOException, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex());
    } 
  }
  
  private static X509Certificate getSignerCert(BasicOCSPResponse paramBasicOCSPResponse, X509Certificate paramX509Certificate1, X509Certificate paramX509Certificate2, JcaJceHelper paramJcaJceHelper) throws NoSuchProviderException, NoSuchAlgorithmException {
    ResponderID responderID = paramBasicOCSPResponse.getTbsResponseData().getResponderID();
    byte[] arrayOfByte = responderID.getKeyHash();
    if (arrayOfByte != null) {
      MessageDigest messageDigest = paramJcaJceHelper.createMessageDigest("SHA1");
      X509Certificate x509Certificate = paramX509Certificate2;
      if (x509Certificate != null && Arrays.areEqual(arrayOfByte, calcKeyHash(messageDigest, x509Certificate.getPublicKey())))
        return x509Certificate; 
      x509Certificate = paramX509Certificate1;
      if (x509Certificate != null && Arrays.areEqual(arrayOfByte, calcKeyHash(messageDigest, x509Certificate.getPublicKey())))
        return x509Certificate; 
    } else {
      X500Name x500Name = X500Name.getInstance(BCStrictStyle.INSTANCE, responderID.getName());
      X509Certificate x509Certificate = paramX509Certificate2;
      if (x509Certificate != null && x500Name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, x509Certificate.getSubjectX500Principal().getEncoded())))
        return x509Certificate; 
      x509Certificate = paramX509Certificate1;
      if (x509Certificate != null && x500Name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, x509Certificate.getSubjectX500Principal().getEncoded())))
        return x509Certificate; 
    } 
    return null;
  }
  
  private static boolean responderMatches(ResponderID paramResponderID, X509Certificate paramX509Certificate, JcaJceHelper paramJcaJceHelper) throws NoSuchProviderException, NoSuchAlgorithmException {
    byte[] arrayOfByte = paramResponderID.getKeyHash();
    if (arrayOfByte != null) {
      MessageDigest messageDigest = paramJcaJceHelper.createMessageDigest("SHA1");
      return Arrays.areEqual(arrayOfByte, calcKeyHash(messageDigest, paramX509Certificate.getPublicKey()));
    } 
    X500Name x500Name = X500Name.getInstance(BCStrictStyle.INSTANCE, paramResponderID.getName());
    return x500Name.equals(X500Name.getInstance(BCStrictStyle.INSTANCE, paramX509Certificate.getSubjectX500Principal().getEncoded()));
  }
  
  private static byte[] calcKeyHash(MessageDigest paramMessageDigest, PublicKey paramPublicKey) {
    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(paramPublicKey.getEncoded());
    return paramMessageDigest.digest(subjectPublicKeyInfo.getPublicKeyData().getBytes());
  }
  
  private Certificate extractCert() throws CertPathValidatorException {
    try {
      return Certificate.getInstance(this.parameters.getSigningCert().getEncoded());
    } catch (Exception exception) {
      throw new CertPathValidatorException("cannot process signing cert: " + exception.getMessage(), exception, this.parameters.getCertPath(), this.parameters.getIndex());
    } 
  }
  
  private CertID createCertID(CertID paramCertID, Certificate paramCertificate, ASN1Integer paramASN1Integer) throws CertPathValidatorException {
    return createCertID(paramCertID.getHashAlgorithm(), paramCertificate, paramASN1Integer);
  }
  
  private CertID createCertID(AlgorithmIdentifier paramAlgorithmIdentifier, Certificate paramCertificate, ASN1Integer paramASN1Integer) throws CertPathValidatorException {
    try {
      MessageDigest messageDigest = this.helper.createMessageDigest(MessageDigestUtils.getDigestName(paramAlgorithmIdentifier.getAlgorithm()));
      DEROctetString dEROctetString1 = new DEROctetString(messageDigest.digest(paramCertificate.getSubject().getEncoded("DER")));
      DEROctetString dEROctetString2 = new DEROctetString(messageDigest.digest(paramCertificate.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
      return new CertID(paramAlgorithmIdentifier, dEROctetString1, dEROctetString2, paramASN1Integer);
    } catch (Exception exception) {
      throw new CertPathValidatorException("problem creating ID: " + exception, exception);
    } 
  }
  
  private static String getDigestName(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    String str = MessageDigestUtils.getDigestName(paramASN1ObjectIdentifier);
    int i = str.indexOf('-');
    return (i > 0 && !str.startsWith("SHA3")) ? (str.substring(0, i) + str.substring(i + 1)) : str;
  }
  
  private static String getSignatureName(AlgorithmIdentifier paramAlgorithmIdentifier) {
    ASN1Encodable aSN1Encodable = paramAlgorithmIdentifier.getParameters();
    if (aSN1Encodable != null && !DERNull.INSTANCE.equals(aSN1Encodable) && paramAlgorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS)) {
      RSASSAPSSparams rSASSAPSSparams = RSASSAPSSparams.getInstance(aSN1Encodable);
      return getDigestName(rSASSAPSSparams.getHashAlgorithm().getAlgorithm()) + "WITHRSAANDMGF1";
    } 
    return oids.containsKey(paramAlgorithmIdentifier.getAlgorithm()) ? (String)oids.get(paramAlgorithmIdentifier.getAlgorithm()) : paramAlgorithmIdentifier.getAlgorithm().getId();
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
