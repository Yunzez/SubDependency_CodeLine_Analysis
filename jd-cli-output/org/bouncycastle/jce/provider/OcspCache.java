package org.bouncycastle.jce.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPRequest;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.Request;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.ocsp.TBSRequest;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.io.Streams;

class OcspCache {
  private static final int DEFAULT_TIMEOUT = 15000;
  
  private static final int DEFAULT_MAX_RESPONSE_SIZE = 32768;
  
  private static Map<URI, WeakReference<Map<CertID, OCSPResponse>>> cache = Collections.synchronizedMap(new WeakHashMap<URI, WeakReference<Map<CertID, OCSPResponse>>>());
  
  static OCSPResponse getOcspResponse(CertID paramCertID, PKIXCertRevocationCheckerParameters paramPKIXCertRevocationCheckerParameters, URI paramURI, X509Certificate paramX509Certificate, List<Extension> paramList, JcaJceHelper paramJcaJceHelper) throws CertPathValidatorException {
    URL uRL;
    Map<CertID, OCSPResponse> map = null;
    WeakReference<Map> weakReference = (WeakReference)cache.get(paramURI);
    if (weakReference != null)
      map = weakReference.get(); 
    if (map != null) {
      OCSPResponse oCSPResponse = (OCSPResponse)map.get(paramCertID);
      if (oCSPResponse != null) {
        BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(ASN1OctetString.getInstance(oCSPResponse.getResponseBytes().getResponse()).getOctets());
        ResponseData responseData = ResponseData.getInstance(basicOCSPResponse.getTbsResponseData());
        ASN1Sequence aSN1Sequence = responseData.getResponses();
        for (byte b1 = 0; b1 != aSN1Sequence.size(); b1++) {
          SingleResponse singleResponse = SingleResponse.getInstance(aSN1Sequence.getObjectAt(b1));
          if (paramCertID.equals(singleResponse.getCertID())) {
            ASN1GeneralizedTime aSN1GeneralizedTime = singleResponse.getNextUpdate();
            try {
              if (aSN1GeneralizedTime != null && paramPKIXCertRevocationCheckerParameters.getValidDate().after(aSN1GeneralizedTime.getDate())) {
                map.remove(paramCertID);
                oCSPResponse = null;
              } 
            } catch (ParseException parseException) {
              map.remove(paramCertID);
              oCSPResponse = null;
            } 
          } 
        } 
        if (oCSPResponse != null)
          return oCSPResponse; 
      } 
    } 
    try {
      uRL = paramURI.toURL();
    } catch (MalformedURLException malformedURLException) {
      throw new CertPathValidatorException("configuration error: " + malformedURLException.getMessage(), malformedURLException, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex());
    } 
    ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector();
    aSN1EncodableVector1.add(new Request(paramCertID, null));
    List<Extension> list = paramList;
    ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
    byte[] arrayOfByte = null;
    for (byte b = 0; b != list.size(); b++) {
      Extension extension = list.get(b);
      byte[] arrayOfByte1 = extension.getValue();
      if (OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId().equals(extension.getId()))
        arrayOfByte = arrayOfByte1; 
      aSN1EncodableVector2.add(new Extension(new ASN1ObjectIdentifier(extension.getId()), extension.isCritical(), arrayOfByte1));
    } 
    TBSRequest tBSRequest = new TBSRequest(null, new DERSequence(aSN1EncodableVector1), Extensions.getInstance(new DERSequence(aSN1EncodableVector2)));
    Signature signature = null;
    try {
      byte[] arrayOfByte1 = (new OCSPRequest(tBSRequest, signature)).getEncoded();
      HttpURLConnection httpURLConnection = (HttpURLConnection)uRL.openConnection();
      httpURLConnection.setConnectTimeout(15000);
      httpURLConnection.setReadTimeout(15000);
      httpURLConnection.setDoOutput(true);
      httpURLConnection.setDoInput(true);
      httpURLConnection.setRequestMethod("POST");
      httpURLConnection.setRequestProperty("Content-type", "application/ocsp-request");
      httpURLConnection.setRequestProperty("Content-length", String.valueOf(arrayOfByte1.length));
      OutputStream outputStream = httpURLConnection.getOutputStream();
      outputStream.write(arrayOfByte1);
      outputStream.flush();
      InputStream inputStream = httpURLConnection.getInputStream();
      int i = httpURLConnection.getContentLength();
      if (i < 0)
        i = 32768; 
      OCSPResponse oCSPResponse = OCSPResponse.getInstance(Streams.readAllLimited(inputStream, i));
      if (0 == oCSPResponse.getResponseStatus().getIntValue()) {
        boolean bool = false;
        ResponseBytes responseBytes = ResponseBytes.getInstance(oCSPResponse.getResponseBytes());
        if (responseBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
          BasicOCSPResponse basicOCSPResponse = BasicOCSPResponse.getInstance(responseBytes.getResponse().getOctets());
          bool = ProvOcspRevocationChecker.validatedOcspResponse(basicOCSPResponse, paramPKIXCertRevocationCheckerParameters, arrayOfByte, paramX509Certificate, paramJcaJceHelper);
        } 
        if (!bool)
          throw new CertPathValidatorException("OCSP response failed to validate", null, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex()); 
        weakReference = (WeakReference<Map>)cache.get(paramURI);
        if (weakReference != null) {
          map = weakReference.get();
          map.put(paramCertID, oCSPResponse);
        } else {
          map = new HashMap<CertID, OCSPResponse>();
          map.put(paramCertID, oCSPResponse);
          cache.put(paramURI, new WeakReference<Map<CertID, OCSPResponse>>(map));
        } 
        return oCSPResponse;
      } 
      throw new CertPathValidatorException("OCSP responder failed: " + oCSPResponse.getResponseStatus().getValue(), null, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex());
    } catch (IOException iOException) {
      throw new CertPathValidatorException("configuration error: " + iOException.getMessage(), iOException, paramPKIXCertRevocationCheckerParameters.getCertPath(), paramPKIXCertRevocationCheckerParameters.getIndex());
    } 
  }
}
