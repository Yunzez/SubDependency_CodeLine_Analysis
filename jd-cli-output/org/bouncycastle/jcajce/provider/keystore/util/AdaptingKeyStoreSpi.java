package org.bouncycastle.jcajce.provider.keystore.util;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Properties;

public class AdaptingKeyStoreSpi extends KeyStoreSpi {
  public static final String COMPAT_OVERRIDE = "keystore.type.compat";
  
  private final JKSKeyStoreSpi jksStore;
  
  private final KeyStoreSpi primaryStore;
  
  private KeyStoreSpi keyStoreSpi;
  
  public AdaptingKeyStoreSpi(JcaJceHelper paramJcaJceHelper, KeyStoreSpi paramKeyStoreSpi) {
    this.jksStore = new JKSKeyStoreSpi(paramJcaJceHelper);
    this.primaryStore = paramKeyStoreSpi;
    this.keyStoreSpi = paramKeyStoreSpi;
  }
  
  public boolean engineProbe(InputStream paramInputStream) throws IOException {
    return (this.keyStoreSpi instanceof PKCS12KeyStoreSpi) ? ((PKCS12KeyStoreSpi)this.keyStoreSpi).engineProbe(paramInputStream) : false;
  }
  
  public Key engineGetKey(String paramString, char[] paramArrayOfchar) throws NoSuchAlgorithmException, UnrecoverableKeyException {
    return this.keyStoreSpi.engineGetKey(paramString, paramArrayOfchar);
  }
  
  public Certificate[] engineGetCertificateChain(String paramString) {
    return this.keyStoreSpi.engineGetCertificateChain(paramString);
  }
  
  public Certificate engineGetCertificate(String paramString) {
    return this.keyStoreSpi.engineGetCertificate(paramString);
  }
  
  public Date engineGetCreationDate(String paramString) {
    return this.keyStoreSpi.engineGetCreationDate(paramString);
  }
  
  public void engineSetKeyEntry(String paramString, Key paramKey, char[] paramArrayOfchar, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    this.keyStoreSpi.engineSetKeyEntry(paramString, paramKey, paramArrayOfchar, paramArrayOfCertificate);
  }
  
  public void engineSetKeyEntry(String paramString, byte[] paramArrayOfbyte, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    this.keyStoreSpi.engineSetKeyEntry(paramString, paramArrayOfbyte, paramArrayOfCertificate);
  }
  
  public void engineSetCertificateEntry(String paramString, Certificate paramCertificate) throws KeyStoreException {
    this.keyStoreSpi.engineSetCertificateEntry(paramString, paramCertificate);
  }
  
  public void engineDeleteEntry(String paramString) throws KeyStoreException {
    this.keyStoreSpi.engineDeleteEntry(paramString);
  }
  
  public Enumeration<String> engineAliases() {
    return this.keyStoreSpi.engineAliases();
  }
  
  public boolean engineContainsAlias(String paramString) {
    return this.keyStoreSpi.engineContainsAlias(paramString);
  }
  
  public int engineSize() {
    return this.keyStoreSpi.engineSize();
  }
  
  public boolean engineIsKeyEntry(String paramString) {
    return this.keyStoreSpi.engineIsKeyEntry(paramString);
  }
  
  public boolean engineIsCertificateEntry(String paramString) {
    return this.keyStoreSpi.engineIsCertificateEntry(paramString);
  }
  
  public String engineGetCertificateAlias(Certificate paramCertificate) {
    return this.keyStoreSpi.engineGetCertificateAlias(paramCertificate);
  }
  
  public void engineStore(OutputStream paramOutputStream, char[] paramArrayOfchar) throws IOException, NoSuchAlgorithmException, CertificateException {
    this.keyStoreSpi.engineStore(paramOutputStream, paramArrayOfchar);
  }
  
  public void engineStore(KeyStore.LoadStoreParameter paramLoadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
    this.keyStoreSpi.engineStore(paramLoadStoreParameter);
  }
  
  public void engineLoad(InputStream paramInputStream, char[] paramArrayOfchar) throws IOException, NoSuchAlgorithmException, CertificateException {
    if (paramInputStream == null) {
      this.keyStoreSpi = this.primaryStore;
      this.keyStoreSpi.engineLoad((InputStream)null, paramArrayOfchar);
    } else {
      if (Properties.isOverrideSet("keystore.type.compat") || !(this.primaryStore instanceof PKCS12KeyStoreSpi)) {
        if (!paramInputStream.markSupported())
          paramInputStream = new BufferedInputStream(paramInputStream); 
        paramInputStream.mark(8);
        if (this.jksStore.engineProbe(paramInputStream)) {
          this.keyStoreSpi = this.jksStore;
        } else {
          this.keyStoreSpi = this.primaryStore;
        } 
        paramInputStream.reset();
      } else {
        this.keyStoreSpi = this.primaryStore;
      } 
      this.keyStoreSpi.engineLoad(paramInputStream, paramArrayOfchar);
    } 
  }
  
  public void engineLoad(KeyStore.LoadStoreParameter paramLoadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
    this.keyStoreSpi.engineLoad(paramLoadStoreParameter);
  }
}
