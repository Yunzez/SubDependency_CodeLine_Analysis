package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

abstract class X509CRLImpl extends X509CRL {
  protected JcaJceHelper bcHelper;
  
  protected CertificateList c;
  
  protected String sigAlgName;
  
  protected byte[] sigAlgParams;
  
  protected boolean isIndirect;
  
  X509CRLImpl(JcaJceHelper paramJcaJceHelper, CertificateList paramCertificateList, String paramString, byte[] paramArrayOfbyte, boolean paramBoolean) {
    this.bcHelper = paramJcaJceHelper;
    this.c = paramCertificateList;
    this.sigAlgName = paramString;
    this.sigAlgParams = paramArrayOfbyte;
    this.isIndirect = paramBoolean;
  }
  
  public boolean hasUnsupportedCriticalExtension() {
    Set set = getCriticalExtensionOIDs();
    if (set == null)
      return false; 
    set.remove(Extension.issuingDistributionPoint.getId());
    set.remove(Extension.deltaCRLIndicator.getId());
    return !set.isEmpty();
  }
  
  private Set getExtensionOIDs(boolean paramBoolean) {
    if (getVersion() == 2) {
      Extensions extensions = this.c.getTBSCertList().getExtensions();
      if (extensions != null) {
        HashSet<String> hashSet = new HashSet();
        Enumeration<ASN1ObjectIdentifier> enumeration = extensions.oids();
        while (enumeration.hasMoreElements()) {
          ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
          Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
          if (paramBoolean == extension.isCritical())
            hashSet.add(aSN1ObjectIdentifier.getId()); 
        } 
        return hashSet;
      } 
    } 
    return null;
  }
  
  public Set getCriticalExtensionOIDs() {
    return getExtensionOIDs(true);
  }
  
  public Set getNonCriticalExtensionOIDs() {
    return getExtensionOIDs(false);
  }
  
  public byte[] getExtensionValue(String paramString) {
    ASN1OctetString aSN1OctetString = getExtensionValue(this.c, paramString);
    if (null != aSN1OctetString)
      try {
        return aSN1OctetString.getEncoded();
      } catch (Exception exception) {
        throw new IllegalStateException("error parsing " + exception.toString());
      }  
    return null;
  }
  
  public void verify(PublicKey paramPublicKey) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    doVerify(paramPublicKey, new SignatureCreator() {
          public Signature createSignature(String param1String) throws NoSuchAlgorithmException, NoSuchProviderException {
            try {
              return X509CRLImpl.this.bcHelper.createSignature(param1String);
            } catch (Exception exception) {
              return Signature.getInstance(param1String);
            } 
          }
        });
  }
  
  public void verify(PublicKey paramPublicKey, final String sigProvider) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    doVerify(paramPublicKey, new SignatureCreator() {
          public Signature createSignature(String param1String) throws NoSuchAlgorithmException, NoSuchProviderException {
            return (sigProvider != null) ? Signature.getInstance(param1String, sigProvider) : Signature.getInstance(param1String);
          }
        });
  }
  
  public void verify(PublicKey paramPublicKey, final Provider sigProvider) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    try {
      doVerify(paramPublicKey, new SignatureCreator() {
            public Signature createSignature(String param1String) throws NoSuchAlgorithmException, NoSuchProviderException {
              return (sigProvider != null) ? Signature.getInstance(X509CRLImpl.this.getSigAlgName(), sigProvider) : Signature.getInstance(X509CRLImpl.this.getSigAlgName());
            }
          });
    } catch (NoSuchProviderException noSuchProviderException) {
      throw new NoSuchAlgorithmException("provider issue: " + noSuchProviderException.getMessage());
    } 
  }
  
  private void doVerify(PublicKey paramPublicKey, SignatureCreator paramSignatureCreator) throws CRLException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
    if (!this.c.getSignatureAlgorithm().equals(this.c.getTBSCertList().getSignature()))
      throw new CRLException("Signature algorithm on CertificateList does not match TBSCertList."); 
    if (paramPublicKey instanceof CompositePublicKey && X509SignatureUtil.isCompositeAlgorithm(this.c.getSignatureAlgorithm())) {
      List<PublicKey> list = ((CompositePublicKey)paramPublicKey).getPublicKeys();
      ASN1Sequence aSN1Sequence1 = ASN1Sequence.getInstance(this.c.getSignatureAlgorithm().getParameters());
      ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(DERBitString.getInstance(this.c.getSignature()).getBytes());
      boolean bool = false;
      for (byte b = 0; b != list.size(); b++) {
        if (list.get(b) != null) {
          AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(aSN1Sequence1.getObjectAt(b));
          String str = X509SignatureUtil.getSignatureName(algorithmIdentifier);
          Signature signature = paramSignatureCreator.createSignature(str);
          SignatureException signatureException = null;
          try {
            checkSignature(list.get(b), signature, algorithmIdentifier.getParameters(), DERBitString.getInstance(aSN1Sequence2.getObjectAt(b)).getBytes());
            bool = true;
          } catch (SignatureException signatureException1) {
            signatureException = signatureException1;
          } 
          if (signatureException != null)
            throw signatureException; 
        } 
      } 
      if (!bool)
        throw new InvalidKeyException("no matching key found"); 
    } else if (X509SignatureUtil.isCompositeAlgorithm(this.c.getSignatureAlgorithm())) {
      ASN1Sequence aSN1Sequence1 = ASN1Sequence.getInstance(this.c.getSignatureAlgorithm().getParameters());
      ASN1Sequence aSN1Sequence2 = ASN1Sequence.getInstance(DERBitString.getInstance(this.c.getSignature()).getBytes());
      boolean bool = false;
      for (byte b = 0; b != aSN1Sequence2.size(); b++) {
        AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(aSN1Sequence1.getObjectAt(b));
        String str = X509SignatureUtil.getSignatureName(algorithmIdentifier);
        SignatureException signatureException = null;
        try {
          Signature signature = paramSignatureCreator.createSignature(str);
          checkSignature(paramPublicKey, signature, algorithmIdentifier.getParameters(), DERBitString.getInstance(aSN1Sequence2.getObjectAt(b)).getBytes());
          bool = true;
        } catch (InvalidKeyException invalidKeyException) {
        
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
        
        } catch (SignatureException signatureException1) {
          signatureException = signatureException1;
        } 
        if (signatureException != null)
          throw signatureException; 
      } 
      if (!bool)
        throw new InvalidKeyException("no matching key found"); 
    } else {
      Signature signature = paramSignatureCreator.createSignature(getSigAlgName());
      if (this.sigAlgParams == null) {
        checkSignature(paramPublicKey, signature, null, getSignature());
      } else {
        try {
          checkSignature(paramPublicKey, signature, ASN1Primitive.fromByteArray(this.sigAlgParams), getSignature());
        } catch (IOException iOException) {
          throw new SignatureException("cannot decode signature parameters: " + iOException.getMessage());
        } 
      } 
    } 
  }
  
  private void checkSignature(PublicKey paramPublicKey, Signature paramSignature, ASN1Encodable paramASN1Encodable, byte[] paramArrayOfbyte) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, CRLException {
    if (paramASN1Encodable != null)
      X509SignatureUtil.setSignatureParameters(paramSignature, paramASN1Encodable); 
    paramSignature.initVerify(paramPublicKey);
    try {
      BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(OutputStreamFactory.createStream(paramSignature), 512);
      this.c.getTBSCertList().encodeTo(bufferedOutputStream, "DER");
      bufferedOutputStream.close();
    } catch (IOException iOException) {
      throw new CRLException(iOException.toString());
    } 
    if (!paramSignature.verify(paramArrayOfbyte))
      throw new SignatureException("CRL does not verify with supplied public key."); 
  }
  
  public int getVersion() {
    return this.c.getVersionNumber();
  }
  
  public Principal getIssuerDN() {
    return new X509Principal(X500Name.getInstance(this.c.getIssuer().toASN1Primitive()));
  }
  
  public X500Principal getIssuerX500Principal() {
    try {
      return new X500Principal(this.c.getIssuer().getEncoded());
    } catch (IOException iOException) {
      throw new IllegalStateException("can't encode issuer DN");
    } 
  }
  
  public Date getThisUpdate() {
    return this.c.getThisUpdate().getDate();
  }
  
  public Date getNextUpdate() {
    Time time = this.c.getNextUpdate();
    return (null == time) ? null : time.getDate();
  }
  
  private Set loadCRLEntries() {
    HashSet<X509CRLEntryObject> hashSet = new HashSet();
    Enumeration<TBSCertList.CRLEntry> enumeration = this.c.getRevokedCertificateEnumeration();
    X500Name x500Name = null;
    while (enumeration.hasMoreElements()) {
      TBSCertList.CRLEntry cRLEntry = enumeration.nextElement();
      X509CRLEntryObject x509CRLEntryObject = new X509CRLEntryObject(cRLEntry, this.isIndirect, x500Name);
      hashSet.add(x509CRLEntryObject);
      if (this.isIndirect && cRLEntry.hasExtensions()) {
        Extension extension = cRLEntry.getExtensions().getExtension(Extension.certificateIssuer);
        if (extension != null)
          x500Name = X500Name.getInstance(GeneralNames.getInstance(extension.getParsedValue()).getNames()[0].getName()); 
      } 
    } 
    return hashSet;
  }
  
  public X509CRLEntry getRevokedCertificate(BigInteger paramBigInteger) {
    Enumeration<TBSCertList.CRLEntry> enumeration = this.c.getRevokedCertificateEnumeration();
    X500Name x500Name = null;
    while (enumeration.hasMoreElements()) {
      TBSCertList.CRLEntry cRLEntry = enumeration.nextElement();
      if (cRLEntry.getUserCertificate().hasValue(paramBigInteger))
        return new X509CRLEntryObject(cRLEntry, this.isIndirect, x500Name); 
      if (this.isIndirect && cRLEntry.hasExtensions()) {
        Extension extension = cRLEntry.getExtensions().getExtension(Extension.certificateIssuer);
        if (extension != null)
          x500Name = X500Name.getInstance(GeneralNames.getInstance(extension.getParsedValue()).getNames()[0].getName()); 
      } 
    } 
    return null;
  }
  
  public Set getRevokedCertificates() {
    Set<?> set = loadCRLEntries();
    return !set.isEmpty() ? Collections.unmodifiableSet(set) : null;
  }
  
  public byte[] getTBSCertList() throws CRLException {
    try {
      return this.c.getTBSCertList().getEncoded("DER");
    } catch (IOException iOException) {
      throw new CRLException(iOException.toString());
    } 
  }
  
  public byte[] getSignature() {
    return this.c.getSignature().getOctets();
  }
  
  public String getSigAlgName() {
    return this.sigAlgName;
  }
  
  public String getSigAlgOID() {
    return this.c.getSignatureAlgorithm().getAlgorithm().getId();
  }
  
  public byte[] getSigAlgParams() {
    return Arrays.clone(this.sigAlgParams);
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append("              Version: ").append(getVersion()).append(str);
    stringBuffer.append("             IssuerDN: ").append(getIssuerDN()).append(str);
    stringBuffer.append("          This update: ").append(getThisUpdate()).append(str);
    stringBuffer.append("          Next update: ").append(getNextUpdate()).append(str);
    stringBuffer.append("  Signature Algorithm: ").append(getSigAlgName()).append(str);
    X509SignatureUtil.prettyPrintSignature(getSignature(), stringBuffer, str);
    Extensions extensions = this.c.getTBSCertList().getExtensions();
    if (extensions != null) {
      Enumeration<ASN1ObjectIdentifier> enumeration = extensions.oids();
      if (enumeration.hasMoreElements())
        stringBuffer.append("           Extensions: ").append(str); 
      while (enumeration.hasMoreElements()) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
        Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
        if (extension.getExtnValue() != null) {
          byte[] arrayOfByte = extension.getExtnValue().getOctets();
          ASN1InputStream aSN1InputStream = new ASN1InputStream(arrayOfByte);
          stringBuffer.append("                       critical(").append(extension.isCritical()).append(") ");
          try {
            if (aSN1ObjectIdentifier.equals(Extension.cRLNumber)) {
              stringBuffer.append(new CRLNumber(ASN1Integer.getInstance(aSN1InputStream.readObject()).getPositiveValue())).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(Extension.deltaCRLIndicator)) {
              stringBuffer.append("Base CRL: " + new CRLNumber(ASN1Integer.getInstance(aSN1InputStream.readObject()).getPositiveValue())).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(Extension.issuingDistributionPoint)) {
              stringBuffer.append(IssuingDistributionPoint.getInstance(aSN1InputStream.readObject())).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(Extension.cRLDistributionPoints)) {
              stringBuffer.append(CRLDistPoint.getInstance(aSN1InputStream.readObject())).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(Extension.freshestCRL)) {
              stringBuffer.append(CRLDistPoint.getInstance(aSN1InputStream.readObject())).append(str);
              continue;
            } 
            stringBuffer.append(aSN1ObjectIdentifier.getId());
            stringBuffer.append(" value = ").append(ASN1Dump.dumpAsString(aSN1InputStream.readObject())).append(str);
          } catch (Exception exception) {
            stringBuffer.append(aSN1ObjectIdentifier.getId());
            stringBuffer.append(" value = ").append("*****").append(str);
          } 
          continue;
        } 
        stringBuffer.append(str);
      } 
    } 
    Set set = getRevokedCertificates();
    if (set != null) {
      Iterator iterator = set.iterator();
      while (iterator.hasNext()) {
        stringBuffer.append(iterator.next());
        stringBuffer.append(str);
      } 
    } 
    return stringBuffer.toString();
  }
  
  public boolean isRevoked(Certificate paramCertificate) {
    if (!paramCertificate.getType().equals("X.509"))
      throw new IllegalArgumentException("X.509 CRL used with non X.509 Cert"); 
    Enumeration enumeration = this.c.getRevokedCertificateEnumeration();
    X500Name x500Name = this.c.getIssuer();
    if (enumeration.hasMoreElements()) {
      BigInteger bigInteger = ((X509Certificate)paramCertificate).getSerialNumber();
      while (enumeration.hasMoreElements()) {
        TBSCertList.CRLEntry cRLEntry = TBSCertList.CRLEntry.getInstance(enumeration.nextElement());
        if (this.isIndirect && cRLEntry.hasExtensions()) {
          Extension extension = cRLEntry.getExtensions().getExtension(Extension.certificateIssuer);
          if (extension != null)
            x500Name = X500Name.getInstance(GeneralNames.getInstance(extension.getParsedValue()).getNames()[0].getName()); 
        } 
        if (cRLEntry.getUserCertificate().hasValue(bigInteger)) {
          X500Name x500Name1;
          if (paramCertificate instanceof X509Certificate) {
            x500Name1 = X500Name.getInstance(((X509Certificate)paramCertificate).getIssuerX500Principal().getEncoded());
          } else {
            try {
              x500Name1 = Certificate.getInstance(paramCertificate.getEncoded()).getIssuer();
            } catch (CertificateEncodingException certificateEncodingException) {
              throw new IllegalArgumentException("Cannot process certificate: " + certificateEncodingException.getMessage());
            } 
          } 
          return !!x500Name.equals(x500Name1);
        } 
      } 
    } 
    return false;
  }
  
  protected static byte[] getExtensionOctets(CertificateList paramCertificateList, String paramString) {
    ASN1OctetString aSN1OctetString = getExtensionValue(paramCertificateList, paramString);
    return (null != aSN1OctetString) ? aSN1OctetString.getOctets() : null;
  }
  
  protected static ASN1OctetString getExtensionValue(CertificateList paramCertificateList, String paramString) {
    Extensions extensions = paramCertificateList.getTBSCertList().getExtensions();
    if (null != extensions) {
      Extension extension = extensions.getExtension(new ASN1ObjectIdentifier(paramString));
      if (null != extension)
        return extension.getExtnValue(); 
    } 
    return null;
  }
}
