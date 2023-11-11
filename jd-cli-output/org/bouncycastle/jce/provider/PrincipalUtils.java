package org.bouncycastle.jce.provider;

import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.jcajce.interfaces.BCX509Certificate;
import org.bouncycastle.x509.X509AttributeCertificate;

class PrincipalUtils {
  static X500Name getCA(TrustAnchor paramTrustAnchor) {
    return getX500Name(notNull(paramTrustAnchor).getCA());
  }
  
  static X500Name getEncodedIssuerPrincipal(Object paramObject) {
    return (paramObject instanceof X509Certificate) ? getIssuerPrincipal((X509Certificate)paramObject) : getX500Name((X500Principal)((X509AttributeCertificate)paramObject).getIssuer().getPrincipals()[0]);
  }
  
  static X500Name getIssuerPrincipal(X509Certificate paramX509Certificate) {
    return (paramX509Certificate instanceof BCX509Certificate) ? notNull(((BCX509Certificate)paramX509Certificate).getIssuerX500Name()) : getX500Name(notNull(paramX509Certificate).getIssuerX500Principal());
  }
  
  static X500Name getIssuerPrincipal(X509CRL paramX509CRL) {
    return getX500Name(notNull(paramX509CRL).getIssuerX500Principal());
  }
  
  static X500Name getSubjectPrincipal(X509Certificate paramX509Certificate) {
    return (paramX509Certificate instanceof BCX509Certificate) ? notNull(((BCX509Certificate)paramX509Certificate).getSubjectX500Name()) : getX500Name(notNull(paramX509Certificate).getSubjectX500Principal());
  }
  
  static X500Name getX500Name(X500Principal paramX500Principal) {
    X500Name x500Name = X500Name.getInstance(getEncoded(paramX500Principal));
    return notNull(x500Name);
  }
  
  static X500Name getX500Name(X500NameStyle paramX500NameStyle, X500Principal paramX500Principal) {
    X500Name x500Name = X500Name.getInstance(paramX500NameStyle, getEncoded(paramX500Principal));
    return notNull(x500Name);
  }
  
  private static byte[] getEncoded(X500Principal paramX500Principal) {
    byte[] arrayOfByte = notNull(paramX500Principal).getEncoded();
    return notNull(arrayOfByte);
  }
  
  private static byte[] notNull(byte[] paramArrayOfbyte) {
    if (null == paramArrayOfbyte)
      throw new IllegalStateException(); 
    return paramArrayOfbyte;
  }
  
  private static TrustAnchor notNull(TrustAnchor paramTrustAnchor) {
    if (null == paramTrustAnchor)
      throw new IllegalStateException(); 
    return paramTrustAnchor;
  }
  
  private static X509Certificate notNull(X509Certificate paramX509Certificate) {
    if (null == paramX509Certificate)
      throw new IllegalStateException(); 
    return paramX509Certificate;
  }
  
  private static X509CRL notNull(X509CRL paramX509CRL) {
    if (null == paramX509CRL)
      throw new IllegalStateException(); 
    return paramX509CRL;
  }
  
  private static X500Name notNull(X500Name paramX500Name) {
    if (null == paramX500Name)
      throw new IllegalStateException(); 
    return paramX500Name;
  }
  
  private static X500Principal notNull(X500Principal paramX500Principal) {
    if (null == paramX500Principal)
      throw new IllegalStateException(); 
    return paramX500Principal;
  }
}
