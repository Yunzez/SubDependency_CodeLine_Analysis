package org.bouncycastle.jcajce.provider.keystore.pkcs12;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.GOST28147Parameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.CertBag;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.EncryptedData;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.SafeBag;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.jcajce.PKCS12Key;
import org.bouncycastle.jcajce.PKCS12StoreParameter;
import org.bouncycastle.jcajce.provider.keystore.util.AdaptingKeyStoreSpi;
import org.bouncycastle.jcajce.provider.keystore.util.ParameterUtil;
import org.bouncycastle.jcajce.spec.GOST28147ParameterSpec;
import org.bouncycastle.jcajce.spec.PBKDF2KeySpec;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.jce.interfaces.BCKeyStore;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JDKPKCS12StoreParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PKCS12KeyStoreSpi extends KeyStoreSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers, BCKeyStore {
  static final String PKCS12_MAX_IT_COUNT_PROPERTY = "org.bouncycastle.pkcs12.max_it_count";
  
  private final JcaJceHelper helper = new BCJcaJceHelper();
  
  private static final int SALT_SIZE = 20;
  
  private static final int MIN_ITERATIONS = 51200;
  
  private static final DefaultSecretKeyProvider keySizeProvider = new DefaultSecretKeyProvider();
  
  private IgnoresCaseHashtable keys = new IgnoresCaseHashtable();
  
  private IgnoresCaseHashtable localIds = new IgnoresCaseHashtable();
  
  private IgnoresCaseHashtable certs = new IgnoresCaseHashtable();
  
  private Hashtable chainCerts = new Hashtable<Object, Object>();
  
  private Hashtable keyCerts = new Hashtable<Object, Object>();
  
  static final int NULL = 0;
  
  static final int CERTIFICATE = 1;
  
  static final int KEY = 2;
  
  static final int SECRET = 3;
  
  static final int SEALED = 4;
  
  static final int KEY_PRIVATE = 0;
  
  static final int KEY_PUBLIC = 1;
  
  static final int KEY_SECRET = 2;
  
  protected SecureRandom random = CryptoServicesRegistrar.getSecureRandom();
  
  private CertificateFactory certFact;
  
  private ASN1ObjectIdentifier keyAlgorithm;
  
  private ASN1ObjectIdentifier certAlgorithm;
  
  private AlgorithmIdentifier macAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
  
  private int itCount = 102400;
  
  private int saltLength = 20;
  
  public PKCS12KeyStoreSpi(JcaJceHelper paramJcaJceHelper, ASN1ObjectIdentifier paramASN1ObjectIdentifier1, ASN1ObjectIdentifier paramASN1ObjectIdentifier2) {
    this.keyAlgorithm = paramASN1ObjectIdentifier1;
    this.certAlgorithm = paramASN1ObjectIdentifier2;
    try {
      this.certFact = paramJcaJceHelper.createCertificateFactory("X.509");
    } catch (Exception exception) {
      throw new IllegalArgumentException("can't create cert factory - " + exception.toString());
    } 
  }
  
  private SubjectKeyIdentifier createSubjectKeyId(PublicKey paramPublicKey) {
    try {
      SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(paramPublicKey.getEncoded());
      return new SubjectKeyIdentifier(getDigest(subjectPublicKeyInfo));
    } catch (Exception exception) {
      throw new RuntimeException("error creating key");
    } 
  }
  
  private static byte[] getDigest(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    Digest digest = DigestFactory.createSHA1();
    byte[] arrayOfByte1 = new byte[digest.getDigestSize()];
    byte[] arrayOfByte2 = paramSubjectPublicKeyInfo.getPublicKeyData().getBytes();
    digest.update(arrayOfByte2, 0, arrayOfByte2.length);
    digest.doFinal(arrayOfByte1, 0);
    return arrayOfByte1;
  }
  
  public void setRandom(SecureRandom paramSecureRandom) {
    this.random = paramSecureRandom;
  }
  
  public boolean engineProbe(InputStream paramInputStream) throws IOException {
    return false;
  }
  
  public Enumeration engineAliases() {
    Hashtable<Object, Object> hashtable = new Hashtable<Object, Object>();
    Enumeration<String> enumeration = this.certs.keys();
    while (enumeration.hasMoreElements())
      hashtable.put(enumeration.nextElement(), "cert"); 
    enumeration = this.keys.keys();
    while (enumeration.hasMoreElements()) {
      String str = enumeration.nextElement();
      if (hashtable.get(str) == null)
        hashtable.put(str, "key"); 
    } 
    return hashtable.keys();
  }
  
  public boolean engineContainsAlias(String paramString) {
    return (this.certs.get(paramString) != null || this.keys.get(paramString) != null);
  }
  
  public void engineDeleteEntry(String paramString) throws KeyStoreException {
    Key key = (Key)this.keys.remove(paramString);
    Certificate certificate = (Certificate)this.certs.remove(paramString);
    if (certificate != null)
      this.chainCerts.remove(new CertId(certificate.getPublicKey())); 
    if (key != null) {
      String str = (String)this.localIds.remove(paramString);
      if (str != null)
        certificate = (Certificate)this.keyCerts.remove(str); 
      if (certificate != null)
        this.chainCerts.remove(new CertId(certificate.getPublicKey())); 
    } 
  }
  
  public Certificate engineGetCertificate(String paramString) {
    if (paramString == null)
      throw new IllegalArgumentException("null alias passed to getCertificate."); 
    Certificate certificate = (Certificate)this.certs.get(paramString);
    if (certificate == null) {
      String str = (String)this.localIds.get(paramString);
      if (str != null) {
        certificate = (Certificate)this.keyCerts.get(str);
      } else {
        certificate = (Certificate)this.keyCerts.get(paramString);
      } 
    } 
    return certificate;
  }
  
  public String engineGetCertificateAlias(Certificate paramCertificate) {
    Enumeration<Certificate> enumeration = this.certs.elements();
    Enumeration<String> enumeration1 = this.certs.keys();
    while (enumeration.hasMoreElements()) {
      Certificate certificate = enumeration.nextElement();
      String str = enumeration1.nextElement();
      if (certificate.equals(paramCertificate))
        return str; 
    } 
    enumeration = this.keyCerts.elements();
    enumeration1 = this.keyCerts.keys();
    while (enumeration.hasMoreElements()) {
      Certificate certificate = enumeration.nextElement();
      String str = enumeration1.nextElement();
      if (certificate.equals(paramCertificate))
        return str; 
    } 
    return null;
  }
  
  public Certificate[] engineGetCertificateChain(String paramString) {
    if (paramString == null)
      throw new IllegalArgumentException("null alias passed to getCertificateChain."); 
    if (!engineIsKeyEntry(paramString))
      return null; 
    Certificate certificate = engineGetCertificate(paramString);
    if (certificate != null) {
      Vector<Certificate> vector = new Vector();
      while (certificate != null) {
        X509Certificate x509Certificate = (X509Certificate)certificate;
        Certificate certificate1 = null;
        byte[] arrayOfByte = x509Certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        if (arrayOfByte != null) {
          ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance(arrayOfByte);
          AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(aSN1OctetString.getOctets());
          byte[] arrayOfByte1 = authorityKeyIdentifier.getKeyIdentifier();
          if (null != arrayOfByte1)
            certificate1 = (Certificate)this.chainCerts.get(new CertId(arrayOfByte1)); 
        } 
        if (certificate1 == null) {
          Principal principal1 = x509Certificate.getIssuerDN();
          Principal principal2 = x509Certificate.getSubjectDN();
          if (!principal1.equals(principal2)) {
            Enumeration enumeration = this.chainCerts.keys();
            while (enumeration.hasMoreElements()) {
              X509Certificate x509Certificate1 = (X509Certificate)this.chainCerts.get(enumeration.nextElement());
              Principal principal = x509Certificate1.getSubjectDN();
              if (principal.equals(principal1))
                try {
                  x509Certificate.verify(x509Certificate1.getPublicKey());
                  certificate1 = x509Certificate1;
                  break;
                } catch (Exception exception) {} 
            } 
          } 
        } 
        if (vector.contains(certificate)) {
          certificate = null;
          continue;
        } 
        vector.addElement(certificate);
        if (certificate1 != certificate) {
          certificate = certificate1;
          continue;
        } 
        certificate = null;
      } 
      Certificate[] arrayOfCertificate = new Certificate[vector.size()];
      for (byte b = 0; b != arrayOfCertificate.length; b++)
        arrayOfCertificate[b] = vector.elementAt(b); 
      return arrayOfCertificate;
    } 
    return null;
  }
  
  public Date engineGetCreationDate(String paramString) {
    if (paramString == null)
      throw new NullPointerException("alias == null"); 
    return (this.keys.get(paramString) == null && this.certs.get(paramString) == null) ? null : new Date();
  }
  
  public Key engineGetKey(String paramString, char[] paramArrayOfchar) throws NoSuchAlgorithmException, UnrecoverableKeyException {
    if (paramString == null)
      throw new IllegalArgumentException("null alias passed to getKey."); 
    return (Key)this.keys.get(paramString);
  }
  
  public boolean engineIsCertificateEntry(String paramString) {
    return (this.certs.get(paramString) != null && this.keys.get(paramString) == null);
  }
  
  public boolean engineIsKeyEntry(String paramString) {
    return (this.keys.get(paramString) != null);
  }
  
  public void engineSetCertificateEntry(String paramString, Certificate paramCertificate) throws KeyStoreException {
    if (this.keys.get(paramString) != null)
      throw new KeyStoreException("There is a key entry with the name " + paramString + "."); 
    this.certs.put(paramString, paramCertificate);
    this.chainCerts.put(new CertId(paramCertificate.getPublicKey()), paramCertificate);
  }
  
  public void engineSetKeyEntry(String paramString, byte[] paramArrayOfbyte, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    throw new RuntimeException("operation not supported");
  }
  
  public void engineSetKeyEntry(String paramString, Key paramKey, char[] paramArrayOfchar, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    if (!(paramKey instanceof PrivateKey))
      throw new KeyStoreException("PKCS12 does not support non-PrivateKeys"); 
    if (paramKey instanceof PrivateKey && paramArrayOfCertificate == null)
      throw new KeyStoreException("no certificate chain for private key"); 
    if (this.keys.get(paramString) != null)
      engineDeleteEntry(paramString); 
    this.keys.put(paramString, paramKey);
    if (paramArrayOfCertificate != null) {
      this.certs.put(paramString, paramArrayOfCertificate[0]);
      for (byte b = 0; b != paramArrayOfCertificate.length; b++)
        this.chainCerts.put(new CertId(paramArrayOfCertificate[b].getPublicKey()), paramArrayOfCertificate[b]); 
    } 
  }
  
  public int engineSize() {
    Hashtable<Object, Object> hashtable = new Hashtable<Object, Object>();
    Enumeration<String> enumeration = this.certs.keys();
    while (enumeration.hasMoreElements())
      hashtable.put(enumeration.nextElement(), "cert"); 
    enumeration = this.keys.keys();
    while (enumeration.hasMoreElements()) {
      String str = enumeration.nextElement();
      if (hashtable.get(str) == null)
        hashtable.put(str, "key"); 
    } 
    return hashtable.size();
  }
  
  protected PrivateKey unwrapKey(AlgorithmIdentifier paramAlgorithmIdentifier, byte[] paramArrayOfbyte, char[] paramArrayOfchar, boolean paramBoolean) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramAlgorithmIdentifier.getAlgorithm();
    try {
      if (aSN1ObjectIdentifier.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
        PKCS12PBEParams pKCS12PBEParams = PKCS12PBEParams.getInstance(paramAlgorithmIdentifier.getParameters());
        PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(pKCS12PBEParams.getIV(), validateIterationCount(pKCS12PBEParams.getIterations()));
        Cipher cipher = this.helper.createCipher(aSN1ObjectIdentifier.getId());
        PKCS12Key pKCS12Key = new PKCS12Key(paramArrayOfchar, paramBoolean);
        cipher.init(4, pKCS12Key, pBEParameterSpec);
        return (PrivateKey)cipher.unwrap(paramArrayOfbyte, "", 2);
      } 
      if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.id_PBES2)) {
        Cipher cipher = createCipher(4, paramArrayOfchar, paramAlgorithmIdentifier);
        return (PrivateKey)cipher.unwrap(paramArrayOfbyte, "", 2);
      } 
    } catch (Exception exception) {
      throw new IOException("exception unwrapping private key - " + exception.toString());
    } 
    throw new IOException("exception unwrapping private key - cannot recognise: " + aSN1ObjectIdentifier);
  }
  
  protected byte[] wrapKey(String paramString, Key paramKey, PKCS12PBEParams paramPKCS12PBEParams, char[] paramArrayOfchar) throws IOException {
    byte[] arrayOfByte;
    PBEKeySpec pBEKeySpec = new PBEKeySpec(paramArrayOfchar);
    try {
      SecretKeyFactory secretKeyFactory = this.helper.createSecretKeyFactory(paramString);
      PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(paramPKCS12PBEParams.getIV(), paramPKCS12PBEParams.getIterations().intValue());
      Cipher cipher = this.helper.createCipher(paramString);
      cipher.init(3, secretKeyFactory.generateSecret(pBEKeySpec), pBEParameterSpec);
      arrayOfByte = cipher.wrap(paramKey);
    } catch (Exception exception) {
      throw new IOException("exception encrypting data - " + exception.toString());
    } 
    return arrayOfByte;
  }
  
  protected byte[] cryptData(boolean paramBoolean1, AlgorithmIdentifier paramAlgorithmIdentifier, char[] paramArrayOfchar, boolean paramBoolean2, byte[] paramArrayOfbyte) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramAlgorithmIdentifier.getAlgorithm();
    boolean bool = paramBoolean1 ? true : true;
    if (aSN1ObjectIdentifier.on(PKCSObjectIdentifiers.pkcs_12PbeIds)) {
      PKCS12PBEParams pKCS12PBEParams = PKCS12PBEParams.getInstance(paramAlgorithmIdentifier.getParameters());
      try {
        PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(pKCS12PBEParams.getIV(), pKCS12PBEParams.getIterations().intValue());
        PKCS12Key pKCS12Key = new PKCS12Key(paramArrayOfchar, paramBoolean2);
        Cipher cipher = this.helper.createCipher(aSN1ObjectIdentifier.getId());
        cipher.init(bool, pKCS12Key, pBEParameterSpec);
        return cipher.doFinal(paramArrayOfbyte);
      } catch (Exception exception) {
        throw new IOException("exception decrypting data - " + exception.toString());
      } 
    } 
    if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.id_PBES2))
      try {
        Cipher cipher = createCipher(bool, paramArrayOfchar, paramAlgorithmIdentifier);
        return cipher.doFinal(paramArrayOfbyte);
      } catch (Exception exception) {
        throw new IOException("exception decrypting data - " + exception.toString());
      }  
    throw new IOException("unknown PBE algorithm: " + aSN1ObjectIdentifier);
  }
  
  private Cipher createCipher(int paramInt, char[] paramArrayOfchar, AlgorithmIdentifier paramAlgorithmIdentifier) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
    SecretKey secretKey;
    PBES2Parameters pBES2Parameters = PBES2Parameters.getInstance(paramAlgorithmIdentifier.getParameters());
    PBKDF2Params pBKDF2Params = PBKDF2Params.getInstance(pBES2Parameters.getKeyDerivationFunc().getParameters());
    AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(pBES2Parameters.getEncryptionScheme());
    SecretKeyFactory secretKeyFactory = this.helper.createSecretKeyFactory(pBES2Parameters.getKeyDerivationFunc().getAlgorithm().getId());
    if (pBKDF2Params.isDefaultPrf()) {
      secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(paramArrayOfchar, pBKDF2Params.getSalt(), validateIterationCount(pBKDF2Params.getIterationCount()), keySizeProvider.getKeySize(algorithmIdentifier)));
    } else {
      secretKey = secretKeyFactory.generateSecret(new PBKDF2KeySpec(paramArrayOfchar, pBKDF2Params.getSalt(), validateIterationCount(pBKDF2Params.getIterationCount()), keySizeProvider.getKeySize(algorithmIdentifier), pBKDF2Params.getPrf()));
    } 
    Cipher cipher = this.helper.createCipher(pBES2Parameters.getEncryptionScheme().getAlgorithm().getId());
    ASN1Encodable aSN1Encodable = pBES2Parameters.getEncryptionScheme().getParameters();
    if (aSN1Encodable instanceof ASN1OctetString) {
      cipher.init(paramInt, secretKey, new IvParameterSpec(ASN1OctetString.getInstance(aSN1Encodable).getOctets()));
    } else {
      GOST28147Parameters gOST28147Parameters = GOST28147Parameters.getInstance(aSN1Encodable);
      cipher.init(paramInt, secretKey, new GOST28147ParameterSpec(gOST28147Parameters.getEncryptionParamSet(), gOST28147Parameters.getIV()));
    } 
    return cipher;
  }
  
  public void engineLoad(KeyStore.LoadStoreParameter paramLoadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
    if (paramLoadStoreParameter == null) {
      engineLoad((InputStream)null, (char[])null);
    } else if (paramLoadStoreParameter instanceof BCLoadStoreParameter) {
      BCLoadStoreParameter bCLoadStoreParameter = (BCLoadStoreParameter)paramLoadStoreParameter;
      engineLoad(bCLoadStoreParameter.getInputStream(), ParameterUtil.extractPassword(paramLoadStoreParameter));
    } else {
      throw new IllegalArgumentException("no support for 'param' of type " + paramLoadStoreParameter.getClass().getName());
    } 
  }
  
  public void engineLoad(InputStream paramInputStream, char[] paramArrayOfchar) throws IOException {
    Pfx pfx;
    if (paramInputStream == null)
      return; 
    BufferedInputStream bufferedInputStream = new BufferedInputStream(paramInputStream);
    bufferedInputStream.mark(10);
    int i = bufferedInputStream.read();
    if (i < 0)
      throw new EOFException("no data in keystore stream"); 
    if (i != 48)
      throw new IOException("stream does not represent a PKCS12 key store"); 
    bufferedInputStream.reset();
    ASN1InputStream aSN1InputStream = new ASN1InputStream(bufferedInputStream);
    try {
      pfx = Pfx.getInstance(aSN1InputStream.readObject());
    } catch (Exception exception) {
      throw new IOException(exception.getMessage());
    } 
    ContentInfo contentInfo = pfx.getAuthSafe();
    Vector<SafeBag> vector = new Vector();
    boolean bool1 = false;
    boolean bool2 = false;
    if (pfx.getMacData() != null) {
      if (paramArrayOfchar == null)
        throw new NullPointerException("no password supplied when one expected"); 
      MacData macData = pfx.getMacData();
      DigestInfo digestInfo = macData.getMac();
      this.macAlgorithm = digestInfo.getAlgorithmId();
      byte[] arrayOfByte1 = macData.getSalt();
      this.itCount = validateIterationCount(macData.getIterationCount());
      this.saltLength = arrayOfByte1.length;
      byte[] arrayOfByte2 = ((ASN1OctetString)contentInfo.getContent()).getOctets();
      try {
        byte[] arrayOfByte3 = calculatePbeMac(this.macAlgorithm.getAlgorithm(), arrayOfByte1, this.itCount, paramArrayOfchar, false, arrayOfByte2);
        byte[] arrayOfByte4 = digestInfo.getDigest();
        if (!Arrays.constantTimeAreEqual(arrayOfByte3, arrayOfByte4)) {
          if (paramArrayOfchar.length > 0)
            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file."); 
          arrayOfByte3 = calculatePbeMac(this.macAlgorithm.getAlgorithm(), arrayOfByte1, this.itCount, paramArrayOfchar, true, arrayOfByte2);
          if (!Arrays.constantTimeAreEqual(arrayOfByte3, arrayOfByte4))
            throw new IOException("PKCS12 key store mac invalid - wrong password or corrupted file."); 
          bool2 = true;
        } 
      } catch (IOException iOException) {
        throw iOException;
      } catch (Exception exception) {
        throw new IOException("error constructing MAC: " + exception.toString());
      } 
    } else if (paramArrayOfchar != null && paramArrayOfchar.length != 0 && !Properties.isOverrideSet("org.bouncycastle.pkcs12.ignore_useless_passwd")) {
      throw new IOException("password supplied for keystore that does not require one");
    } 
    this.keys = new IgnoresCaseHashtable();
    this.localIds = new IgnoresCaseHashtable();
    if (contentInfo.getContentType().equals(data)) {
      ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance(contentInfo.getContent());
      AuthenticatedSafe authenticatedSafe = AuthenticatedSafe.getInstance(aSN1OctetString.getOctets());
      ContentInfo[] arrayOfContentInfo = authenticatedSafe.getContentInfo();
      for (byte b1 = 0; b1 != arrayOfContentInfo.length; b1++) {
        if (arrayOfContentInfo[b1].getContentType().equals(data)) {
          ASN1OctetString aSN1OctetString1 = ASN1OctetString.getInstance(arrayOfContentInfo[b1].getContent());
          ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(aSN1OctetString1.getOctets());
          for (byte b2 = 0; b2 != aSN1Sequence.size(); b2++) {
            SafeBag safeBag = SafeBag.getInstance(aSN1Sequence.getObjectAt(b2));
            if (safeBag.getBagId().equals(pkcs8ShroudedKeyBag)) {
              EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(safeBag.getBagValue());
              PrivateKey privateKey = unwrapKey(encryptedPrivateKeyInfo.getEncryptionAlgorithm(), encryptedPrivateKeyInfo.getEncryptedData(), paramArrayOfchar, bool2);
              String str = null;
              ASN1OctetString aSN1OctetString2 = null;
              if (safeBag.getBagAttributes() != null) {
                Enumeration<ASN1Sequence> enumeration = safeBag.getBagAttributes().getObjects();
                while (enumeration.hasMoreElements()) {
                  ASN1Sequence aSN1Sequence1 = enumeration.nextElement();
                  ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier)aSN1Sequence1.getObjectAt(0);
                  ASN1Set aSN1Set = (ASN1Set)aSN1Sequence1.getObjectAt(1);
                  ASN1Primitive aSN1Primitive = null;
                  if (aSN1Set.size() > 0) {
                    aSN1Primitive = (ASN1Primitive)aSN1Set.getObjectAt(0);
                    if (privateKey instanceof PKCS12BagAttributeCarrier) {
                      PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)privateKey;
                      ASN1Encodable aSN1Encodable = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
                      if (aSN1Encodable != null) {
                        if (!aSN1Encodable.toASN1Primitive().equals(aSN1Primitive))
                          throw new IOException("attempt to add existing attribute with different value"); 
                      } else {
                        pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Primitive);
                      } 
                    } 
                  } 
                  if (aSN1ObjectIdentifier.equals(pkcs_9_at_friendlyName)) {
                    str = ((ASN1BMPString)aSN1Primitive).getString();
                    this.keys.put(str, privateKey);
                    continue;
                  } 
                  if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId))
                    aSN1OctetString2 = (ASN1OctetString)aSN1Primitive; 
                } 
              } 
              if (aSN1OctetString2 != null) {
                String str1 = new String(Hex.encode(aSN1OctetString2.getOctets()));
                if (str == null) {
                  this.keys.put(str1, privateKey);
                } else {
                  this.localIds.put(str, str1);
                } 
              } else {
                bool1 = true;
                this.keys.put("unmarked", privateKey);
              } 
            } else if (safeBag.getBagId().equals(certBag)) {
              vector.addElement(safeBag);
            } else {
              System.out.println("extra in data " + safeBag.getBagId());
              System.out.println(ASN1Dump.dumpAsString(safeBag));
            } 
          } 
        } else if (arrayOfContentInfo[b1].getContentType().equals(encryptedData)) {
          EncryptedData encryptedData = EncryptedData.getInstance(arrayOfContentInfo[b1].getContent());
          byte[] arrayOfByte = cryptData(false, encryptedData.getEncryptionAlgorithm(), paramArrayOfchar, bool2, encryptedData.getContent().getOctets());
          ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(arrayOfByte);
          for (byte b2 = 0; b2 != aSN1Sequence.size(); b2++) {
            SafeBag safeBag = SafeBag.getInstance(aSN1Sequence.getObjectAt(b2));
            if (safeBag.getBagId().equals(certBag)) {
              vector.addElement(safeBag);
            } else if (safeBag.getBagId().equals(pkcs8ShroudedKeyBag)) {
              EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(safeBag.getBagValue());
              PrivateKey privateKey = unwrapKey(encryptedPrivateKeyInfo.getEncryptionAlgorithm(), encryptedPrivateKeyInfo.getEncryptedData(), paramArrayOfchar, bool2);
              PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)privateKey;
              String str1 = null;
              ASN1OctetString aSN1OctetString1 = null;
              Enumeration<ASN1Sequence> enumeration = safeBag.getBagAttributes().getObjects();
              while (enumeration.hasMoreElements()) {
                ASN1Sequence aSN1Sequence1 = enumeration.nextElement();
                ASN1ObjectIdentifier aSN1ObjectIdentifier = (ASN1ObjectIdentifier)aSN1Sequence1.getObjectAt(0);
                ASN1Set aSN1Set = (ASN1Set)aSN1Sequence1.getObjectAt(1);
                ASN1Primitive aSN1Primitive = null;
                if (aSN1Set.size() > 0) {
                  aSN1Primitive = (ASN1Primitive)aSN1Set.getObjectAt(0);
                  ASN1Encodable aSN1Encodable = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
                  if (aSN1Encodable != null) {
                    if (!aSN1Encodable.toASN1Primitive().equals(aSN1Primitive))
                      throw new IOException("attempt to add existing attribute with different value"); 
                  } else {
                    pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Primitive);
                  } 
                } 
                if (aSN1ObjectIdentifier.equals(pkcs_9_at_friendlyName)) {
                  str1 = ((ASN1BMPString)aSN1Primitive).getString();
                  this.keys.put(str1, privateKey);
                  continue;
                } 
                if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId))
                  aSN1OctetString1 = (ASN1OctetString)aSN1Primitive; 
              } 
              String str2 = new String(Hex.encode(aSN1OctetString1.getOctets()));
              if (str1 == null) {
                this.keys.put(str2, privateKey);
              } else {
                this.localIds.put(str1, str2);
              } 
            } else if (safeBag.getBagId().equals(keyBag)) {
              PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(safeBag.getBagValue());
              PrivateKey privateKey = BouncyCastleProvider.getPrivateKey(privateKeyInfo);
              PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)privateKey;
              String str1 = null;
              ASN1OctetString aSN1OctetString1 = null;
              Enumeration enumeration = safeBag.getBagAttributes().getObjects();
              while (enumeration.hasMoreElements()) {
                ASN1Sequence aSN1Sequence1 = ASN1Sequence.getInstance(enumeration.nextElement());
                ASN1ObjectIdentifier aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(aSN1Sequence1.getObjectAt(0));
                ASN1Set aSN1Set = ASN1Set.getInstance(aSN1Sequence1.getObjectAt(1));
                ASN1Primitive aSN1Primitive = null;
                if (aSN1Set.size() > 0) {
                  aSN1Primitive = (ASN1Primitive)aSN1Set.getObjectAt(0);
                  ASN1Encodable aSN1Encodable = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
                  if (aSN1Encodable != null) {
                    if (!aSN1Encodable.toASN1Primitive().equals(aSN1Primitive))
                      throw new IOException("attempt to add existing attribute with different value"); 
                  } else {
                    pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Primitive);
                  } 
                  if (aSN1ObjectIdentifier.equals(pkcs_9_at_friendlyName)) {
                    str1 = ((ASN1BMPString)aSN1Primitive).getString();
                    this.keys.put(str1, privateKey);
                    continue;
                  } 
                  if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId))
                    aSN1OctetString1 = (ASN1OctetString)aSN1Primitive; 
                } 
              } 
              String str2 = new String(Hex.encode(aSN1OctetString1.getOctets()));
              if (str1 == null) {
                this.keys.put(str2, privateKey);
              } else {
                this.localIds.put(str1, str2);
              } 
            } else {
              System.out.println("extra in encryptedData " + safeBag.getBagId());
              System.out.println(ASN1Dump.dumpAsString(safeBag));
            } 
          } 
        } else {
          System.out.println("extra " + arrayOfContentInfo[b1].getContentType().getId());
          System.out.println("extra " + ASN1Dump.dumpAsString(arrayOfContentInfo[b1].getContent()));
        } 
      } 
    } 
    this.certs = new IgnoresCaseHashtable();
    this.chainCerts = new Hashtable<Object, Object>();
    this.keyCerts = new Hashtable<Object, Object>();
    for (byte b = 0; b != vector.size(); b++) {
      Certificate certificate;
      SafeBag safeBag = vector.elementAt(b);
      CertBag certBag = CertBag.getInstance(safeBag.getBagValue());
      if (!certBag.getCertId().equals(x509Certificate))
        throw new RuntimeException("Unsupported certificate type: " + certBag.getCertId()); 
      try {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(((ASN1OctetString)certBag.getCertValue()).getOctets());
        certificate = this.certFact.generateCertificate(byteArrayInputStream);
      } catch (Exception exception) {
        throw new RuntimeException(exception.toString());
      } 
      ASN1OctetString aSN1OctetString = null;
      String str = null;
      if (safeBag.getBagAttributes() != null) {
        Enumeration enumeration = safeBag.getBagAttributes().getObjects();
        while (enumeration.hasMoreElements()) {
          ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(enumeration.nextElement());
          ASN1ObjectIdentifier aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(aSN1Sequence.getObjectAt(0));
          ASN1Set aSN1Set = ASN1Set.getInstance(aSN1Sequence.getObjectAt(1));
          if (aSN1Set.size() > 0) {
            ASN1Primitive aSN1Primitive = (ASN1Primitive)aSN1Set.getObjectAt(0);
            PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = null;
            if (certificate instanceof PKCS12BagAttributeCarrier) {
              pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)certificate;
              ASN1Encodable aSN1Encodable = pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier);
              if (aSN1Encodable != null) {
                if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId)) {
                  String str1 = Hex.toHexString(((ASN1OctetString)aSN1Primitive).getOctets());
                  if (!this.keys.keys.containsKey(str1) && !this.localIds.keys.containsKey(str1))
                    continue; 
                } 
                if (!aSN1Encodable.toASN1Primitive().equals(aSN1Primitive))
                  throw new IOException("attempt to add existing attribute with different value"); 
              } else {
                pKCS12BagAttributeCarrier.setBagAttribute(aSN1ObjectIdentifier, aSN1Primitive);
              } 
            } 
            if (aSN1ObjectIdentifier.equals(pkcs_9_at_friendlyName)) {
              str = ((ASN1BMPString)aSN1Primitive).getString();
              continue;
            } 
            if (aSN1ObjectIdentifier.equals(pkcs_9_at_localKeyId))
              aSN1OctetString = (ASN1OctetString)aSN1Primitive; 
          } 
        } 
      } 
      this.chainCerts.put(new CertId(certificate.getPublicKey()), certificate);
      if (bool1) {
        if (this.keyCerts.isEmpty()) {
          String str1 = new String(Hex.encode(createSubjectKeyId(certificate.getPublicKey()).getKeyIdentifier()));
          this.keyCerts.put(str1, certificate);
          this.keys.put(str1, this.keys.remove("unmarked"));
        } 
      } else {
        if (aSN1OctetString != null) {
          String str1 = new String(Hex.encode(aSN1OctetString.getOctets()));
          this.keyCerts.put(str1, certificate);
        } 
        if (str != null)
          this.certs.put(str, certificate); 
      } 
    } 
  }
  
  private int validateIterationCount(BigInteger paramBigInteger) {
    int i = paramBigInteger.intValue();
    if (i < 0)
      throw new IllegalStateException("negative iteration count found"); 
    BigInteger bigInteger = Properties.asBigInteger("org.bouncycastle.pkcs12.max_it_count");
    if (bigInteger != null && bigInteger.intValue() < i)
      throw new IllegalStateException("iteration count " + i + " greater than " + bigInteger.intValue()); 
    return i;
  }
  
  public void engineStore(KeyStore.LoadStoreParameter paramLoadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
    PKCS12StoreParameter pKCS12StoreParameter;
    char[] arrayOfChar;
    if (paramLoadStoreParameter == null)
      throw new IllegalArgumentException("'param' arg cannot be null"); 
    if (!(paramLoadStoreParameter instanceof PKCS12StoreParameter) && !(paramLoadStoreParameter instanceof JDKPKCS12StoreParameter))
      throw new IllegalArgumentException("No support for 'param' of type " + paramLoadStoreParameter.getClass().getName()); 
    if (paramLoadStoreParameter instanceof PKCS12StoreParameter) {
      pKCS12StoreParameter = (PKCS12StoreParameter)paramLoadStoreParameter;
    } else {
      pKCS12StoreParameter = new PKCS12StoreParameter(((JDKPKCS12StoreParameter)paramLoadStoreParameter).getOutputStream(), paramLoadStoreParameter.getProtectionParameter(), ((JDKPKCS12StoreParameter)paramLoadStoreParameter).isUseDEREncoding());
    } 
    KeyStore.ProtectionParameter protectionParameter = paramLoadStoreParameter.getProtectionParameter();
    if (protectionParameter == null) {
      arrayOfChar = null;
    } else if (protectionParameter instanceof KeyStore.PasswordProtection) {
      arrayOfChar = ((KeyStore.PasswordProtection)protectionParameter).getPassword();
    } else {
      throw new IllegalArgumentException("No support for protection parameter of type " + protectionParameter.getClass().getName());
    } 
    doStore(pKCS12StoreParameter.getOutputStream(), arrayOfChar, pKCS12StoreParameter.isForDEREncoding());
  }
  
  public void engineStore(OutputStream paramOutputStream, char[] paramArrayOfchar) throws IOException {
    doStore(paramOutputStream, paramArrayOfchar, false);
  }
  
  private void doStore(OutputStream paramOutputStream, char[] paramArrayOfchar, boolean paramBoolean) throws IOException {
    MacData macData;
    if (this.keys.size() == 0) {
      if (paramArrayOfchar == null) {
        Enumeration<String> enumeration = this.certs.keys();
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        while (enumeration.hasMoreElements()) {
          try {
            String str = enumeration.nextElement();
            Certificate certificate = (Certificate)this.certs.get(str);
            SafeBag safeBag = createSafeBag(str, certificate);
            aSN1EncodableVector.add(safeBag);
          } catch (CertificateEncodingException certificateEncodingException) {
            throw new IOException("Error encoding certificate: " + certificateEncodingException.toString());
          } 
        } 
        if (paramBoolean) {
          ContentInfo contentInfo1 = new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString((new DERSequence(aSN1EncodableVector)).getEncoded()));
          Pfx pfx1 = new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString((new DERSequence(contentInfo1)).getEncoded())), null);
          pfx1.encodeTo(paramOutputStream, "DER");
        } else {
          ContentInfo contentInfo1 = new ContentInfo(PKCSObjectIdentifiers.data, new BEROctetString((new BERSequence(aSN1EncodableVector)).getEncoded()));
          Pfx pfx1 = new Pfx(new ContentInfo(PKCSObjectIdentifiers.data, new BEROctetString((new BERSequence(contentInfo1)).getEncoded())), null);
          pfx1.encodeTo(paramOutputStream, "BER");
        } 
        return;
      } 
    } else if (paramArrayOfchar == null) {
      throw new NullPointerException("no password supplied for PKCS#12 KeyStore");
    } 
    ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector();
    Enumeration<String> enumeration1 = this.keys.keys();
    while (enumeration1.hasMoreElements()) {
      byte[] arrayOfByte8 = new byte[20];
      this.random.nextBytes(arrayOfByte8);
      String str = enumeration1.nextElement();
      PrivateKey privateKey = (PrivateKey)this.keys.get(str);
      PKCS12PBEParams pKCS12PBEParams1 = new PKCS12PBEParams(arrayOfByte8, 51200);
      byte[] arrayOfByte9 = wrapKey(this.keyAlgorithm.getId(), privateKey, pKCS12PBEParams1, paramArrayOfchar);
      AlgorithmIdentifier algorithmIdentifier1 = new AlgorithmIdentifier(this.keyAlgorithm, pKCS12PBEParams1.toASN1Primitive());
      EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(algorithmIdentifier1, arrayOfByte9);
      boolean bool = false;
      ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
      if (privateKey instanceof PKCS12BagAttributeCarrier) {
        PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)privateKey;
        ASN1BMPString aSN1BMPString = (ASN1BMPString)pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_friendlyName);
        if (aSN1BMPString == null || !aSN1BMPString.getString().equals(str))
          pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str)); 
        if (pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_localKeyId) == null) {
          Certificate certificate = engineGetCertificate(str);
          pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(certificate.getPublicKey()));
        } 
        Enumeration<ASN1ObjectIdentifier> enumeration = pKCS12BagAttributeCarrier.getBagAttributeKeys();
        while (enumeration.hasMoreElements()) {
          ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
          ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
          aSN1EncodableVector3.add(aSN1ObjectIdentifier);
          aSN1EncodableVector3.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier)));
          bool = true;
          aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
        } 
      } 
      if (!bool) {
        ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
        Certificate certificate = engineGetCertificate(str);
        aSN1EncodableVector3.add(pkcs_9_at_localKeyId);
        aSN1EncodableVector3.add(new DERSet(createSubjectKeyId(certificate.getPublicKey())));
        aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
        aSN1EncodableVector3 = new ASN1EncodableVector();
        aSN1EncodableVector3.add(pkcs_9_at_friendlyName);
        aSN1EncodableVector3.add(new DERSet(new DERBMPString(str)));
        aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
      } 
      SafeBag safeBag = new SafeBag(pkcs8ShroudedKeyBag, encryptedPrivateKeyInfo.toASN1Primitive(), new DERSet(aSN1EncodableVector));
      aSN1EncodableVector1.add(safeBag);
    } 
    byte[] arrayOfByte1 = (new DERSequence(aSN1EncodableVector1)).getEncoded("DER");
    BEROctetString bEROctetString = new BEROctetString(arrayOfByte1);
    byte[] arrayOfByte2 = new byte[20];
    this.random.nextBytes(arrayOfByte2);
    ASN1EncodableVector aSN1EncodableVector2 = new ASN1EncodableVector();
    PKCS12PBEParams pKCS12PBEParams = new PKCS12PBEParams(arrayOfByte2, 51200);
    AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(this.certAlgorithm, pKCS12PBEParams.toASN1Primitive());
    Hashtable<Object, Object> hashtable = new Hashtable<Object, Object>();
    Enumeration<String> enumeration2 = this.keys.keys();
    while (enumeration2.hasMoreElements()) {
      try {
        String str = enumeration2.nextElement();
        Certificate certificate = engineGetCertificate(str);
        boolean bool = false;
        CertBag certBag = new CertBag(x509Certificate, new DEROctetString(certificate.getEncoded()));
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        if (certificate instanceof PKCS12BagAttributeCarrier) {
          PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)certificate;
          ASN1BMPString aSN1BMPString = (ASN1BMPString)pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_friendlyName);
          if (aSN1BMPString == null || !aSN1BMPString.getString().equals(str))
            pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(str)); 
          if (pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_localKeyId) == null)
            pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_localKeyId, createSubjectKeyId(certificate.getPublicKey())); 
          Enumeration<ASN1ObjectIdentifier> enumeration = pKCS12BagAttributeCarrier.getBagAttributeKeys();
          while (enumeration.hasMoreElements()) {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
            ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
            aSN1EncodableVector3.add(aSN1ObjectIdentifier);
            aSN1EncodableVector3.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier)));
            aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
            bool = true;
          } 
        } 
        if (!bool) {
          ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
          aSN1EncodableVector3.add(pkcs_9_at_localKeyId);
          aSN1EncodableVector3.add(new DERSet(createSubjectKeyId(certificate.getPublicKey())));
          aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
          aSN1EncodableVector3 = new ASN1EncodableVector();
          aSN1EncodableVector3.add(pkcs_9_at_friendlyName);
          aSN1EncodableVector3.add(new DERSet(new DERBMPString(str)));
          aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
        } 
        SafeBag safeBag = new SafeBag(certBag, certBag.toASN1Primitive(), new DERSet(aSN1EncodableVector));
        aSN1EncodableVector2.add(safeBag);
        hashtable.put(certificate, certificate);
      } catch (CertificateEncodingException certificateEncodingException) {
        throw new IOException("Error encoding certificate: " + certificateEncodingException.toString());
      } 
    } 
    enumeration2 = this.certs.keys();
    while (enumeration2.hasMoreElements()) {
      try {
        String str = enumeration2.nextElement();
        Certificate certificate = (Certificate)this.certs.get(str);
        if (this.keys.get(str) != null)
          continue; 
        SafeBag safeBag = createSafeBag(str, certificate);
        aSN1EncodableVector2.add(safeBag);
        hashtable.put(certificate, certificate);
      } catch (CertificateEncodingException certificateEncodingException) {
        throw new IOException("Error encoding certificate: " + certificateEncodingException.toString());
      } 
    } 
    Set set = getUsedCertificateSet();
    enumeration2 = this.chainCerts.keys();
    while (enumeration2.hasMoreElements()) {
      try {
        CertId certId = (CertId)enumeration2.nextElement();
        Certificate certificate = (Certificate)this.chainCerts.get(certId);
        if (!set.contains(certificate) || hashtable.get(certificate) != null)
          continue; 
        CertBag certBag = new CertBag(x509Certificate, new DEROctetString(certificate.getEncoded()));
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
        if (certificate instanceof PKCS12BagAttributeCarrier) {
          PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)certificate;
          Enumeration<ASN1ObjectIdentifier> enumeration = pKCS12BagAttributeCarrier.getBagAttributeKeys();
          while (enumeration.hasMoreElements()) {
            ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
            if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId))
              continue; 
            ASN1EncodableVector aSN1EncodableVector3 = new ASN1EncodableVector();
            aSN1EncodableVector3.add(aSN1ObjectIdentifier);
            aSN1EncodableVector3.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier)));
            aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector3));
          } 
        } 
        SafeBag safeBag = new SafeBag(certBag, certBag.toASN1Primitive(), new DERSet(aSN1EncodableVector));
        aSN1EncodableVector2.add(safeBag);
      } catch (CertificateEncodingException certificateEncodingException) {
        throw new IOException("Error encoding certificate: " + certificateEncodingException.toString());
      } 
    } 
    byte[] arrayOfByte3 = (new DERSequence(aSN1EncodableVector2)).getEncoded("DER");
    byte[] arrayOfByte4 = cryptData(true, algorithmIdentifier, paramArrayOfchar, false, arrayOfByte3);
    EncryptedData encryptedData = new EncryptedData(data, algorithmIdentifier, new BEROctetString(arrayOfByte4));
    ContentInfo[] arrayOfContentInfo = { new ContentInfo(data, bEROctetString), new ContentInfo(encryptedData, encryptedData.toASN1Primitive()) };
    AuthenticatedSafe authenticatedSafe = new AuthenticatedSafe(arrayOfContentInfo);
    byte[] arrayOfByte5 = authenticatedSafe.getEncoded(paramBoolean ? "DER" : "BER");
    ContentInfo contentInfo = new ContentInfo(data, new BEROctetString(arrayOfByte5));
    byte[] arrayOfByte6 = new byte[this.saltLength];
    this.random.nextBytes(arrayOfByte6);
    byte[] arrayOfByte7 = ((ASN1OctetString)contentInfo.getContent()).getOctets();
    try {
      byte[] arrayOfByte = calculatePbeMac(this.macAlgorithm.getAlgorithm(), arrayOfByte6, this.itCount, paramArrayOfchar, false, arrayOfByte7);
      DigestInfo digestInfo = new DigestInfo(this.macAlgorithm, arrayOfByte);
      macData = new MacData(digestInfo, arrayOfByte6, this.itCount);
    } catch (Exception exception) {
      throw new IOException("error constructing MAC: " + exception.toString());
    } 
    Pfx pfx = new Pfx(contentInfo, macData);
    pfx.encodeTo(paramOutputStream, paramBoolean ? "DER" : "BER");
  }
  
  private SafeBag createSafeBag(String paramString, Certificate paramCertificate) throws CertificateEncodingException {
    CertBag certBag = new CertBag(x509Certificate, new DEROctetString(paramCertificate.getEncoded()));
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
    boolean bool = false;
    if (paramCertificate instanceof PKCS12BagAttributeCarrier) {
      PKCS12BagAttributeCarrier pKCS12BagAttributeCarrier = (PKCS12BagAttributeCarrier)paramCertificate;
      ASN1BMPString aSN1BMPString = (ASN1BMPString)pKCS12BagAttributeCarrier.getBagAttribute(pkcs_9_at_friendlyName);
      if ((aSN1BMPString == null || !aSN1BMPString.getString().equals(paramString)) && paramString != null)
        pKCS12BagAttributeCarrier.setBagAttribute(pkcs_9_at_friendlyName, new DERBMPString(paramString)); 
      Enumeration<ASN1ObjectIdentifier> enumeration = pKCS12BagAttributeCarrier.getBagAttributeKeys();
      while (enumeration.hasMoreElements()) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = enumeration.nextElement();
        if (aSN1ObjectIdentifier.equals(PKCSObjectIdentifiers.pkcs_9_at_localKeyId))
          continue; 
        ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector();
        aSN1EncodableVector1.add(aSN1ObjectIdentifier);
        aSN1EncodableVector1.add(new DERSet(pKCS12BagAttributeCarrier.getBagAttribute(aSN1ObjectIdentifier)));
        aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector1));
        bool = true;
      } 
    } 
    if (!bool) {
      ASN1EncodableVector aSN1EncodableVector1 = new ASN1EncodableVector();
      aSN1EncodableVector1.add(pkcs_9_at_friendlyName);
      aSN1EncodableVector1.add(new DERSet(new DERBMPString(paramString)));
      aSN1EncodableVector.add(new DERSequence(aSN1EncodableVector1));
    } 
    return new SafeBag(certBag, certBag.toASN1Primitive(), new DERSet(aSN1EncodableVector));
  }
  
  private Set getUsedCertificateSet() {
    HashSet<Certificate> hashSet = new HashSet();
    Enumeration<String> enumeration = this.keys.keys();
    while (enumeration.hasMoreElements()) {
      String str = enumeration.nextElement();
      Certificate[] arrayOfCertificate = engineGetCertificateChain(str);
      for (byte b = 0; b != arrayOfCertificate.length; b++)
        hashSet.add(arrayOfCertificate[b]); 
    } 
    enumeration = this.certs.keys();
    while (enumeration.hasMoreElements()) {
      String str = enumeration.nextElement();
      Certificate certificate = engineGetCertificate(str);
      hashSet.add(certificate);
    } 
    return hashSet;
  }
  
  private byte[] calculatePbeMac(ASN1ObjectIdentifier paramASN1ObjectIdentifier, byte[] paramArrayOfbyte1, int paramInt, char[] paramArrayOfchar, boolean paramBoolean, byte[] paramArrayOfbyte2) throws Exception {
    PBEParameterSpec pBEParameterSpec = new PBEParameterSpec(paramArrayOfbyte1, paramInt);
    Mac mac = this.helper.createMac(paramASN1ObjectIdentifier.getId());
    mac.init(new PKCS12Key(paramArrayOfchar, paramBoolean), pBEParameterSpec);
    mac.update(paramArrayOfbyte2);
    return mac.doFinal();
  }
  
  public static class BCPKCS12KeyStore extends AdaptingKeyStoreSpi {
    public BCPKCS12KeyStore() {
      super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC));
    }
  }
  
  public static class BCPKCS12KeyStore3DES extends AdaptingKeyStoreSpi {
    public BCPKCS12KeyStore3DES() {
      super(new BCJcaJceHelper(), new PKCS12KeyStoreSpi(new BCJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC));
    }
  }
  
  private class CertId {
    byte[] id;
    
    CertId(PublicKey param1PublicKey) {
      this.id = PKCS12KeyStoreSpi.this.createSubjectKeyId(param1PublicKey).getKeyIdentifier();
    }
    
    CertId(byte[] param1ArrayOfbyte) {
      this.id = param1ArrayOfbyte;
    }
    
    public int hashCode() {
      return Arrays.hashCode(this.id);
    }
    
    public boolean equals(Object param1Object) {
      if (param1Object == this)
        return true; 
      if (!(param1Object instanceof CertId))
        return false; 
      CertId certId = (CertId)param1Object;
      return Arrays.areEqual(this.id, certId.id);
    }
  }
  
  public static class DefPKCS12KeyStore extends AdaptingKeyStoreSpi {
    public DefPKCS12KeyStore() {
      super(new DefaultJcaJceHelper(), new PKCS12KeyStoreSpi(new DefaultJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC));
    }
  }
  
  public static class DefPKCS12KeyStore3DES extends AdaptingKeyStoreSpi {
    public DefPKCS12KeyStore3DES() {
      super(new DefaultJcaJceHelper(), new PKCS12KeyStoreSpi(new DefaultJcaJceHelper(), PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC));
    }
  }
  
  private static class DefaultSecretKeyProvider {
    private final Map KEY_SIZES;
    
    DefaultSecretKeyProvider() {
      HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
      hashMap.put(new ASN1ObjectIdentifier("1.2.840.113533.7.66.10"), Integers.valueOf(128));
      hashMap.put(PKCSObjectIdentifiers.des_EDE3_CBC, Integers.valueOf(192));
      hashMap.put(NISTObjectIdentifiers.id_aes128_CBC, Integers.valueOf(128));
      hashMap.put(NISTObjectIdentifiers.id_aes192_CBC, Integers.valueOf(192));
      hashMap.put(NISTObjectIdentifiers.id_aes256_CBC, Integers.valueOf(256));
      hashMap.put(NTTObjectIdentifiers.id_camellia128_cbc, Integers.valueOf(128));
      hashMap.put(NTTObjectIdentifiers.id_camellia192_cbc, Integers.valueOf(192));
      hashMap.put(NTTObjectIdentifiers.id_camellia256_cbc, Integers.valueOf(256));
      hashMap.put(CryptoProObjectIdentifiers.gostR28147_gcfb, Integers.valueOf(256));
      this.KEY_SIZES = Collections.unmodifiableMap(hashMap);
    }
    
    public int getKeySize(AlgorithmIdentifier param1AlgorithmIdentifier) {
      Integer integer = (Integer)this.KEY_SIZES.get(param1AlgorithmIdentifier.getAlgorithm());
      return (integer != null) ? integer.intValue() : -1;
    }
  }
  
  private static class IgnoresCaseHashtable {
    private Hashtable orig = new Hashtable<Object, Object>();
    
    private Hashtable keys = new Hashtable<Object, Object>();
    
    private IgnoresCaseHashtable() {}
    
    public void put(String param1String, Object param1Object) {
      String str1 = (param1String == null) ? null : Strings.toLowerCase(param1String);
      String str2 = (String)this.keys.get(str1);
      if (str2 != null)
        this.orig.remove(str2); 
      this.keys.put(str1, param1String);
      this.orig.put(param1String, param1Object);
    }
    
    public Enumeration keys() {
      return this.orig.keys();
    }
    
    public Object remove(String param1String) {
      String str = (String)this.keys.remove((param1String == null) ? null : Strings.toLowerCase(param1String));
      return (str == null) ? null : this.orig.remove(str);
    }
    
    public Object get(String param1String) {
      String str = (String)this.keys.get((param1String == null) ? null : Strings.toLowerCase(param1String));
      return (str == null) ? null : this.orig.get(str);
    }
    
    public Enumeration elements() {
      return this.orig.elements();
    }
    
    public int size() {
      return this.orig.size();
    }
  }
}
