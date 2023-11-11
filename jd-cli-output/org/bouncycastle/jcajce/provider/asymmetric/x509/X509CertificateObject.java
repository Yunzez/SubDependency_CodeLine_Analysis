package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import java.util.Enumeration;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.util.Arrays;

class X509CertificateObject extends X509CertificateImpl implements PKCS12BagAttributeCarrier {
  private final Object cacheLock = new Object();
  
  private X509CertificateInternal internalCertificateValue;
  
  private X500Principal issuerValue;
  
  private PublicKey publicKeyValue;
  
  private X500Principal subjectValue;
  
  private long[] validityValues;
  
  private volatile boolean hashValueSet;
  
  private volatile int hashValue;
  
  private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();
  
  X509CertificateObject(JcaJceHelper paramJcaJceHelper, Certificate paramCertificate) throws CertificateParsingException {
    super(paramJcaJceHelper, paramCertificate, createBasicConstraints(paramCertificate), createKeyUsage(paramCertificate), createSigAlgName(paramCertificate), createSigAlgParams(paramCertificate));
  }
  
  public void checkValidity(Date paramDate) throws CertificateExpiredException, CertificateNotYetValidException {
    long l = paramDate.getTime();
    long[] arrayOfLong = getValidityValues();
    if (l > arrayOfLong[1])
      throw new CertificateExpiredException("certificate expired on " + this.c.getEndDate().getTime()); 
    if (l < arrayOfLong[0])
      throw new CertificateNotYetValidException("certificate not valid till " + this.c.getStartDate().getTime()); 
  }
  
  public X500Principal getIssuerX500Principal() {
    synchronized (this.cacheLock) {
      if (null != this.issuerValue)
        return this.issuerValue; 
    } 
    X500Principal x500Principal = super.getIssuerX500Principal();
    synchronized (this.cacheLock) {
      if (null == this.issuerValue)
        this.issuerValue = x500Principal; 
      return this.issuerValue;
    } 
  }
  
  public PublicKey getPublicKey() {
    synchronized (this.cacheLock) {
      if (null != this.publicKeyValue)
        return this.publicKeyValue; 
    } 
    PublicKey publicKey = super.getPublicKey();
    if (null == publicKey)
      return null; 
    synchronized (this.cacheLock) {
      if (null == this.publicKeyValue)
        this.publicKeyValue = publicKey; 
      return this.publicKeyValue;
    } 
  }
  
  public X500Principal getSubjectX500Principal() {
    synchronized (this.cacheLock) {
      if (null != this.subjectValue)
        return this.subjectValue; 
    } 
    X500Principal x500Principal = super.getSubjectX500Principal();
    synchronized (this.cacheLock) {
      if (null == this.subjectValue)
        this.subjectValue = x500Principal; 
      return this.subjectValue;
    } 
  }
  
  public long[] getValidityValues() {
    synchronized (this.cacheLock) {
      if (null != this.validityValues)
        return this.validityValues; 
    } 
    long[] arrayOfLong = { getNotBefore().getTime(), getNotAfter().getTime() };
    synchronized (this.cacheLock) {
      if (null == this.validityValues)
        this.validityValues = arrayOfLong; 
      return this.validityValues;
    } 
  }
  
  public byte[] getEncoded() throws CertificateEncodingException {
    return Arrays.clone(getInternalCertificate().getEncoded());
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof X509CertificateObject) {
      X509CertificateObject x509CertificateObject = (X509CertificateObject)paramObject;
      if (this.hashValueSet && x509CertificateObject.hashValueSet) {
        if (this.hashValue != x509CertificateObject.hashValue)
          return false; 
      } else if (null == this.internalCertificateValue || null == x509CertificateObject.internalCertificateValue) {
        ASN1BitString aSN1BitString = this.c.getSignature();
        if (null != aSN1BitString && !aSN1BitString.equals(x509CertificateObject.c.getSignature()))
          return false; 
      } 
      return getInternalCertificate().equals(x509CertificateObject.getInternalCertificate());
    } 
    return getInternalCertificate().equals(paramObject);
  }
  
  public int hashCode() {
    if (!this.hashValueSet) {
      this.hashValue = getInternalCertificate().hashCode();
      this.hashValueSet = true;
    } 
    return this.hashValue;
  }
  
  public int originalHashCode() {
    try {
      int i = 0;
      byte[] arrayOfByte = getInternalCertificate().getEncoded();
      for (byte b = 1; b < arrayOfByte.length; b++)
        i += arrayOfByte[b] * b; 
      return i;
    } catch (CertificateEncodingException certificateEncodingException) {
      return 0;
    } 
  }
  
  public void setBagAttribute(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Encodable paramASN1Encodable) {
    this.attrCarrier.setBagAttribute(paramASN1ObjectIdentifier, paramASN1Encodable);
  }
  
  public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return this.attrCarrier.getBagAttribute(paramASN1ObjectIdentifier);
  }
  
  public Enumeration getBagAttributeKeys() {
    return this.attrCarrier.getBagAttributeKeys();
  }
  
  private X509CertificateInternal getInternalCertificate() {
    synchronized (this.cacheLock) {
      if (null != this.internalCertificateValue)
        return this.internalCertificateValue; 
    } 
    byte[] arrayOfByte = null;
    X509CertificateEncodingException x509CertificateEncodingException = null;
    try {
      arrayOfByte = this.c.getEncoded("DER");
    } catch (IOException iOException) {
      x509CertificateEncodingException = new X509CertificateEncodingException(iOException);
    } 
    X509CertificateInternal x509CertificateInternal = new X509CertificateInternal(this.bcHelper, this.c, this.basicConstraints, this.keyUsage, this.sigAlgName, this.sigAlgParams, arrayOfByte, x509CertificateEncodingException);
    synchronized (this.cacheLock) {
      if (null == this.internalCertificateValue)
        this.internalCertificateValue = x509CertificateInternal; 
      return this.internalCertificateValue;
    } 
  }
  
  private static BasicConstraints createBasicConstraints(Certificate paramCertificate) throws CertificateParsingException {
    try {
      byte[] arrayOfByte = getExtensionOctets(paramCertificate, "2.5.29.19");
      return (null == arrayOfByte) ? null : BasicConstraints.getInstance(ASN1Primitive.fromByteArray(arrayOfByte));
    } catch (Exception exception) {
      throw new CertificateParsingException("cannot construct BasicConstraints: " + exception);
    } 
  }
  
  private static boolean[] createKeyUsage(Certificate paramCertificate) throws CertificateParsingException {
    try {
      byte[] arrayOfByte1 = getExtensionOctets(paramCertificate, "2.5.29.15");
      if (null == arrayOfByte1)
        return null; 
      DERBitString dERBitString = DERBitString.getInstance(ASN1Primitive.fromByteArray(arrayOfByte1));
      byte[] arrayOfByte2 = dERBitString.getBytes();
      int i = arrayOfByte2.length * 8 - dERBitString.getPadBits();
      boolean[] arrayOfBoolean = new boolean[(i < 9) ? 9 : i];
      for (int j = 0; j != i; j++)
        arrayOfBoolean[j] = ((arrayOfByte2[j / 8] & 128 >>> j % 8) != 0); 
      return arrayOfBoolean;
    } catch (Exception exception) {
      throw new CertificateParsingException("cannot construct KeyUsage: " + exception);
    } 
  }
  
  private static String createSigAlgName(Certificate paramCertificate) throws CertificateParsingException {
    try {
      return X509SignatureUtil.getSignatureName(paramCertificate.getSignatureAlgorithm());
    } catch (Exception exception) {
      throw new CertificateParsingException("cannot construct SigAlgName: " + exception);
    } 
  }
  
  private static byte[] createSigAlgParams(Certificate paramCertificate) throws CertificateParsingException {
    try {
      ASN1Encodable aSN1Encodable = paramCertificate.getSignatureAlgorithm().getParameters();
      return (null == aSN1Encodable) ? null : aSN1Encodable.toASN1Primitive().getEncoded("DER");
    } catch (Exception exception) {
      throw new CertificateParsingException("cannot construct SigAlgParams: " + exception);
    } 
  }
  
  private static class X509CertificateEncodingException extends CertificateEncodingException {
    private final Throwable cause;
    
    X509CertificateEncodingException(Throwable param1Throwable) {
      this.cause = param1Throwable;
    }
    
    public Throwable getCause() {
      return this.cause;
    }
  }
}
