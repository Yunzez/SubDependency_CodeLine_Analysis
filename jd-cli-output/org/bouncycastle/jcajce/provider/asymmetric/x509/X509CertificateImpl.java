package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.misc.NetscapeRevocationURL;
import org.bouncycastle.asn1.misc.VerisignCzagExtension;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.jcajce.io.OutputStreamFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

abstract class X509CertificateImpl extends X509Certificate implements BCX509Certificate {
  protected JcaJceHelper bcHelper;
  
  protected Certificate c;
  
  protected BasicConstraints basicConstraints;
  
  protected boolean[] keyUsage;
  
  protected String sigAlgName;
  
  protected byte[] sigAlgParams;
  
  X509CertificateImpl(JcaJceHelper paramJcaJceHelper, Certificate paramCertificate, BasicConstraints paramBasicConstraints, boolean[] paramArrayOfboolean, String paramString, byte[] paramArrayOfbyte) {
    this.bcHelper = paramJcaJceHelper;
    this.c = paramCertificate;
    this.basicConstraints = paramBasicConstraints;
    this.keyUsage = paramArrayOfboolean;
    this.sigAlgName = paramString;
    this.sigAlgParams = paramArrayOfbyte;
  }
  
  public X500Name getIssuerX500Name() {
    return this.c.getIssuer();
  }
  
  public TBSCertificate getTBSCertificateNative() {
    return this.c.getTBSCertificate();
  }
  
  public X500Name getSubjectX500Name() {
    return this.c.getSubject();
  }
  
  public void checkValidity() throws CertificateExpiredException, CertificateNotYetValidException {
    checkValidity(new Date());
  }
  
  public void checkValidity(Date paramDate) throws CertificateExpiredException, CertificateNotYetValidException {
    if (paramDate.getTime() > getNotAfter().getTime())
      throw new CertificateExpiredException("certificate expired on " + this.c.getEndDate().getTime()); 
    if (paramDate.getTime() < getNotBefore().getTime())
      throw new CertificateNotYetValidException("certificate not valid till " + this.c.getStartDate().getTime()); 
  }
  
  public int getVersion() {
    return this.c.getVersionNumber();
  }
  
  public BigInteger getSerialNumber() {
    return this.c.getSerialNumber().getValue();
  }
  
  public Principal getIssuerDN() {
    return new X509Principal(this.c.getIssuer());
  }
  
  public X500Principal getIssuerX500Principal() {
    try {
      byte[] arrayOfByte = this.c.getIssuer().getEncoded("DER");
      return new X500Principal(arrayOfByte);
    } catch (IOException iOException) {
      throw new IllegalStateException("can't encode issuer DN");
    } 
  }
  
  public Principal getSubjectDN() {
    return new X509Principal(this.c.getSubject());
  }
  
  public X500Principal getSubjectX500Principal() {
    try {
      byte[] arrayOfByte = this.c.getSubject().getEncoded("DER");
      return new X500Principal(arrayOfByte);
    } catch (IOException iOException) {
      throw new IllegalStateException("can't encode subject DN");
    } 
  }
  
  public Date getNotBefore() {
    return this.c.getStartDate().getDate();
  }
  
  public Date getNotAfter() {
    return this.c.getEndDate().getDate();
  }
  
  public byte[] getTBSCertificate() throws CertificateEncodingException {
    try {
      return this.c.getTBSCertificate().getEncoded("DER");
    } catch (IOException iOException) {
      throw new CertificateEncodingException(iOException.toString());
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
  
  public boolean[] getIssuerUniqueID() {
    ASN1BitString aSN1BitString = this.c.getTBSCertificate().getIssuerUniqueId();
    if (aSN1BitString != null) {
      byte[] arrayOfByte = aSN1BitString.getBytes();
      boolean[] arrayOfBoolean = new boolean[arrayOfByte.length * 8 - aSN1BitString.getPadBits()];
      for (byte b = 0; b != arrayOfBoolean.length; b++)
        arrayOfBoolean[b] = ((arrayOfByte[b / 8] & 128 >>> b % 8) != 0); 
      return arrayOfBoolean;
    } 
    return null;
  }
  
  public boolean[] getSubjectUniqueID() {
    ASN1BitString aSN1BitString = this.c.getTBSCertificate().getSubjectUniqueId();
    if (aSN1BitString != null) {
      byte[] arrayOfByte = aSN1BitString.getBytes();
      boolean[] arrayOfBoolean = new boolean[arrayOfByte.length * 8 - aSN1BitString.getPadBits()];
      for (byte b = 0; b != arrayOfBoolean.length; b++)
        arrayOfBoolean[b] = ((arrayOfByte[b / 8] & 128 >>> b % 8) != 0); 
      return arrayOfBoolean;
    } 
    return null;
  }
  
  public boolean[] getKeyUsage() {
    return Arrays.clone(this.keyUsage);
  }
  
  public List getExtendedKeyUsage() throws CertificateParsingException {
    byte[] arrayOfByte = getExtensionOctets(this.c, "2.5.29.37");
    if (null == arrayOfByte)
      return null; 
    try {
      ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(arrayOfByte));
      ArrayList<String> arrayList = new ArrayList();
      for (byte b = 0; b != aSN1Sequence.size(); b++)
        arrayList.add(((ASN1ObjectIdentifier)aSN1Sequence.getObjectAt(b)).getId()); 
      return Collections.unmodifiableList(arrayList);
    } catch (Exception exception) {
      throw new CertificateParsingException("error processing extended key usage extension");
    } 
  }
  
  public int getBasicConstraints() {
    return (this.basicConstraints != null) ? (this.basicConstraints.isCA() ? ((this.basicConstraints.getPathLenConstraint() == null) ? Integer.MAX_VALUE : this.basicConstraints.getPathLenConstraint().intValue()) : -1) : -1;
  }
  
  public Collection getSubjectAlternativeNames() throws CertificateParsingException {
    return getAlternativeNames(this.c, Extension.subjectAlternativeName.getId());
  }
  
  public Collection getIssuerAlternativeNames() throws CertificateParsingException {
    return getAlternativeNames(this.c, Extension.issuerAlternativeName.getId());
  }
  
  public Set getCriticalExtensionOIDs() {
    if (getVersion() == 3) {
      HashSet<String> hashSet = new HashSet();
      Extensions extensions = this.c.getTBSCertificate().getExtensions();
      if (extensions != null) {
        Enumeration<ASN1ObjectIdentifier> enumeration = extensions.oids();
        while (enumeration.hasMoreElements()) {
          ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
          Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
          if (extension.isCritical())
            hashSet.add(aSN1ObjectIdentifier.getId()); 
        } 
        return hashSet;
      } 
    } 
    return null;
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
  
  public Set getNonCriticalExtensionOIDs() {
    if (getVersion() == 3) {
      HashSet<String> hashSet = new HashSet();
      Extensions extensions = this.c.getTBSCertificate().getExtensions();
      if (extensions != null) {
        Enumeration<ASN1ObjectIdentifier> enumeration = extensions.oids();
        while (enumeration.hasMoreElements()) {
          ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
          Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
          if (!extension.isCritical())
            hashSet.add(aSN1ObjectIdentifier.getId()); 
        } 
        return hashSet;
      } 
    } 
    return null;
  }
  
  public boolean hasUnsupportedCriticalExtension() {
    if (getVersion() == 3) {
      Extensions extensions = this.c.getTBSCertificate().getExtensions();
      if (extensions != null) {
        Enumeration<ASN1ObjectIdentifier> enumeration = extensions.oids();
        while (enumeration.hasMoreElements()) {
          ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
          if (aSN1ObjectIdentifier.equals(Extension.keyUsage) || aSN1ObjectIdentifier.equals(Extension.certificatePolicies) || aSN1ObjectIdentifier.equals(Extension.policyMappings) || aSN1ObjectIdentifier.equals(Extension.inhibitAnyPolicy) || aSN1ObjectIdentifier.equals(Extension.cRLDistributionPoints) || aSN1ObjectIdentifier.equals(Extension.issuingDistributionPoint) || aSN1ObjectIdentifier.equals(Extension.deltaCRLIndicator) || aSN1ObjectIdentifier.equals(Extension.policyConstraints) || aSN1ObjectIdentifier.equals(Extension.basicConstraints) || aSN1ObjectIdentifier.equals(Extension.subjectAlternativeName) || aSN1ObjectIdentifier.equals(Extension.nameConstraints))
            continue; 
          Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
          if (extension.isCritical())
            return true; 
        } 
      } 
    } 
    return false;
  }
  
  public PublicKey getPublicKey() {
    try {
      return BouncyCastleProvider.getPublicKey(this.c.getSubjectPublicKeyInfo());
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append("  [0]         Version: ").append(getVersion()).append(str);
    stringBuffer.append("         SerialNumber: ").append(getSerialNumber()).append(str);
    stringBuffer.append("             IssuerDN: ").append(getIssuerDN()).append(str);
    stringBuffer.append("           Start Date: ").append(getNotBefore()).append(str);
    stringBuffer.append("           Final Date: ").append(getNotAfter()).append(str);
    stringBuffer.append("            SubjectDN: ").append(getSubjectDN()).append(str);
    stringBuffer.append("           Public Key: ").append(getPublicKey()).append(str);
    stringBuffer.append("  Signature Algorithm: ").append(getSigAlgName()).append(str);
    X509SignatureUtil.prettyPrintSignature(getSignature(), stringBuffer, str);
    Extensions extensions = this.c.getTBSCertificate().getExtensions();
    if (extensions != null) {
      Enumeration<ASN1ObjectIdentifier> enumeration = extensions.oids();
      if (enumeration.hasMoreElements())
        stringBuffer.append("       Extensions: \n"); 
      while (enumeration.hasMoreElements()) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
        Extension extension = extensions.getExtension(aSN1ObjectIdentifier);
        if (extension.getExtnValue() != null) {
          byte[] arrayOfByte = extension.getExtnValue().getOctets();
          ASN1InputStream aSN1InputStream = new ASN1InputStream(arrayOfByte);
          stringBuffer.append("                       critical(").append(extension.isCritical()).append(") ");
          try {
            if (aSN1ObjectIdentifier.equals(Extension.basicConstraints)) {
              stringBuffer.append(BasicConstraints.getInstance(aSN1InputStream.readObject())).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(Extension.keyUsage)) {
              stringBuffer.append(KeyUsage.getInstance(aSN1InputStream.readObject())).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(MiscObjectIdentifiers.netscapeCertType)) {
              stringBuffer.append(new NetscapeCertType(DERBitString.getInstance(aSN1InputStream.readObject()))).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(MiscObjectIdentifiers.netscapeRevocationURL)) {
              stringBuffer.append(new NetscapeRevocationURL(ASN1IA5String.getInstance(aSN1InputStream.readObject()))).append(str);
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(MiscObjectIdentifiers.verisignCzagExtension)) {
              stringBuffer.append(new VerisignCzagExtension(ASN1IA5String.getInstance(aSN1InputStream.readObject()))).append(str);
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
    return stringBuffer.toString();
  }
  
  public final void verify(PublicKey paramPublicKey) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    doVerify(paramPublicKey, new SignatureCreator() {
          public Signature createSignature(String param1String) throws NoSuchAlgorithmException {
            try {
              return X509CertificateImpl.this.bcHelper.createSignature(param1String);
            } catch (Exception exception) {
              return Signature.getInstance(param1String);
            } 
          }
        });
  }
  
  public final void verify(PublicKey paramPublicKey, final String sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
    doVerify(paramPublicKey, new SignatureCreator() {
          public Signature createSignature(String param1String) throws NoSuchAlgorithmException, NoSuchProviderException {
            return (sigProvider != null) ? Signature.getInstance(param1String, sigProvider) : Signature.getInstance(param1String);
          }
        });
  }
  
  public final void verify(PublicKey paramPublicKey, final Provider sigProvider) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    try {
      doVerify(paramPublicKey, new SignatureCreator() {
            public Signature createSignature(String param1String) throws NoSuchAlgorithmException {
              return (sigProvider != null) ? Signature.getInstance(param1String, sigProvider) : Signature.getInstance(param1String);
            }
          });
    } catch (NoSuchProviderException noSuchProviderException) {
      throw new NoSuchAlgorithmException("provider issue: " + noSuchProviderException.getMessage());
    } 
  }
  
  private void doVerify(PublicKey paramPublicKey, SignatureCreator paramSignatureCreator) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
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
      String str = X509SignatureUtil.getSignatureName(this.c.getSignatureAlgorithm());
      Signature signature = paramSignatureCreator.createSignature(str);
      if (paramPublicKey instanceof CompositePublicKey) {
        List<PublicKey> list = ((CompositePublicKey)paramPublicKey).getPublicKeys();
        byte b = 0;
        while (b != list.size()) {
          try {
            checkSignature(list.get(b), signature, this.c.getSignatureAlgorithm().getParameters(), getSignature());
            return;
          } catch (InvalidKeyException invalidKeyException) {
            b++;
          } 
        } 
        throw new InvalidKeyException("no matching signature found");
      } 
      checkSignature(paramPublicKey, signature, this.c.getSignatureAlgorithm().getParameters(), getSignature());
    } 
  }
  
  private void checkSignature(PublicKey paramPublicKey, Signature paramSignature, ASN1Encodable paramASN1Encodable, byte[] paramArrayOfbyte) throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    if (!isAlgIdEqual(this.c.getSignatureAlgorithm(), this.c.getTBSCertificate().getSignature()))
      throw new CertificateException("signature algorithm in TBS cert not same as outer cert"); 
    X509SignatureUtil.setSignatureParameters(paramSignature, paramASN1Encodable);
    paramSignature.initVerify(paramPublicKey);
    try {
      BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(OutputStreamFactory.createStream(paramSignature), 512);
      this.c.getTBSCertificate().encodeTo(bufferedOutputStream, "DER");
      bufferedOutputStream.close();
    } catch (IOException iOException) {
      throw new CertificateEncodingException(iOException.toString());
    } 
    if (!paramSignature.verify(paramArrayOfbyte))
      throw new SignatureException("certificate does not verify with supplied key"); 
  }
  
  private boolean isAlgIdEqual(AlgorithmIdentifier paramAlgorithmIdentifier1, AlgorithmIdentifier paramAlgorithmIdentifier2) {
    if (!paramAlgorithmIdentifier1.getAlgorithm().equals(paramAlgorithmIdentifier2.getAlgorithm()))
      return false; 
    if (Properties.isOverrideSet("org.bouncycastle.x509.allow_absent_equiv_NULL")) {
      if (paramAlgorithmIdentifier1.getParameters() == null)
        return !(paramAlgorithmIdentifier2.getParameters() != null && !paramAlgorithmIdentifier2.getParameters().equals(DERNull.INSTANCE)); 
      if (paramAlgorithmIdentifier2.getParameters() == null)
        return !(paramAlgorithmIdentifier1.getParameters() != null && !paramAlgorithmIdentifier1.getParameters().equals(DERNull.INSTANCE)); 
    } 
    return (paramAlgorithmIdentifier1.getParameters() != null) ? paramAlgorithmIdentifier1.getParameters().equals(paramAlgorithmIdentifier2.getParameters()) : ((paramAlgorithmIdentifier2.getParameters() != null) ? paramAlgorithmIdentifier2.getParameters().equals(paramAlgorithmIdentifier1.getParameters()) : true);
  }
  
  private static Collection getAlternativeNames(Certificate paramCertificate, String paramString) throws CertificateParsingException {
    byte[] arrayOfByte = getExtensionOctets(paramCertificate, paramString);
    if (arrayOfByte == null)
      return null; 
    try {
      ArrayList<?> arrayList = new ArrayList();
      Enumeration enumeration = ASN1Sequence.getInstance(arrayOfByte).getObjects();
      while (enumeration.hasMoreElements()) {
        byte[] arrayOfByte1;
        String str;
        GeneralName generalName = GeneralName.getInstance(enumeration.nextElement());
        ArrayList<Integer> arrayList1 = new ArrayList();
        arrayList1.add(Integers.valueOf(generalName.getTagNo()));
        switch (generalName.getTagNo()) {
          case 0:
          case 3:
          case 5:
            arrayList1.add(generalName.getEncoded());
            break;
          case 4:
            arrayList1.add(X500Name.getInstance(RFC4519Style.INSTANCE, generalName.getName()).toString());
            break;
          case 1:
          case 2:
          case 6:
            arrayList1.add(((ASN1String)generalName.getName()).getString());
            break;
          case 8:
            arrayList1.add(ASN1ObjectIdentifier.getInstance(generalName.getName()).getId());
            break;
          case 7:
            arrayOfByte1 = DEROctetString.getInstance(generalName.getName()).getOctets();
            try {
              str = InetAddress.getByAddress(arrayOfByte1).getHostAddress();
            } catch (UnknownHostException unknownHostException) {
              continue;
            } 
            arrayList1.add(str);
            break;
          default:
            throw new IOException("Bad tag number: " + generalName.getTagNo());
        } 
        arrayList.add(Collections.unmodifiableList(arrayList1));
      } 
      return (arrayList.size() == 0) ? null : Collections.unmodifiableCollection(arrayList);
    } catch (Exception exception) {
      throw new CertificateParsingException(exception.getMessage());
    } 
  }
  
  protected static byte[] getExtensionOctets(Certificate paramCertificate, String paramString) {
    ASN1OctetString aSN1OctetString = getExtensionValue(paramCertificate, paramString);
    return (null != aSN1OctetString) ? aSN1OctetString.getOctets() : null;
  }
  
  protected static ASN1OctetString getExtensionValue(Certificate paramCertificate, String paramString) {
    Extensions extensions = paramCertificate.getTBSCertificate().getExtensions();
    if (null != extensions) {
      Extension extension = extensions.getExtension(new ASN1ObjectIdentifier(paramString));
      if (null != extension)
        return extension.getExtnValue(); 
    } 
    return null;
  }
}
