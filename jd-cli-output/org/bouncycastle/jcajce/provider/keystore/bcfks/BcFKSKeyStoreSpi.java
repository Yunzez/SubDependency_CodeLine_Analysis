package org.bouncycastle.jcajce.provider.keystore.bcfks;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.bc.EncryptedObjectStoreData;
import org.bouncycastle.asn1.bc.EncryptedPrivateKeyData;
import org.bouncycastle.asn1.bc.EncryptedSecretKeyData;
import org.bouncycastle.asn1.bc.ObjectData;
import org.bouncycastle.asn1.bc.ObjectDataSequence;
import org.bouncycastle.asn1.bc.ObjectStore;
import org.bouncycastle.asn1.bc.ObjectStoreData;
import org.bouncycastle.asn1.bc.ObjectStoreIntegrityCheck;
import org.bouncycastle.asn1.bc.PbkdMacIntegrityCheck;
import org.bouncycastle.asn1.bc.SecretKeyData;
import org.bouncycastle.asn1.bc.SignatureCheck;
import org.bouncycastle.asn1.kisa.KISAObjectIdentifiers;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.ScryptParams;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.nsri.NSRIObjectIdentifiers;
import org.bouncycastle.asn1.ntt.NTTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.crypto.util.PBKDFConfig;
import org.bouncycastle.crypto.util.ScryptConfig;
import org.bouncycastle.internal.asn1.cms.CCMParameters;
import org.bouncycastle.jcajce.BCFKSLoadStoreParameter;
import org.bouncycastle.jcajce.BCFKSStoreParameter;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.jcajce.provider.keystore.util.AdaptingKeyStoreSpi;
import org.bouncycastle.jcajce.provider.keystore.util.ParameterUtil;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

class BcFKSKeyStoreSpi extends KeyStoreSpi {
  private static final Map<String, ASN1ObjectIdentifier> oidMap = new HashMap<String, ASN1ObjectIdentifier>();
  
  private static final Map<ASN1ObjectIdentifier, String> publicAlgMap = new HashMap<ASN1ObjectIdentifier, String>();
  
  private PublicKey verificationKey;
  
  private BCFKSLoadStoreParameter.CertChainValidator validator;
  
  private static final BigInteger CERTIFICATE = BigInteger.valueOf(0L);
  
  private static final BigInteger PRIVATE_KEY = BigInteger.valueOf(1L);
  
  private static final BigInteger SECRET_KEY = BigInteger.valueOf(2L);
  
  private static final BigInteger PROTECTED_PRIVATE_KEY = BigInteger.valueOf(3L);
  
  private static final BigInteger PROTECTED_SECRET_KEY = BigInteger.valueOf(4L);
  
  private final JcaJceHelper helper;
  
  private final Map<String, ObjectData> entries = new HashMap<String, ObjectData>();
  
  private final Map<String, PrivateKey> privateKeyCache = new HashMap<String, PrivateKey>();
  
  private AlgorithmIdentifier hmacAlgorithm;
  
  private KeyDerivationFunc hmacPkbdAlgorithm;
  
  private AlgorithmIdentifier signatureAlgorithm;
  
  private Date creationDate;
  
  private Date lastModifiedDate;
  
  private ASN1ObjectIdentifier storeEncryptionAlgorithm = NISTObjectIdentifiers.id_aes256_CCM;
  
  private static String getPublicKeyAlg(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    String str = publicAlgMap.get(paramASN1ObjectIdentifier);
    return (str != null) ? str : paramASN1ObjectIdentifier.getId();
  }
  
  BcFKSKeyStoreSpi(JcaJceHelper paramJcaJceHelper) {
    this.helper = paramJcaJceHelper;
  }
  
  public Key engineGetKey(String paramString, char[] paramArrayOfchar) throws NoSuchAlgorithmException, UnrecoverableKeyException {
    ObjectData objectData = this.entries.get(paramString);
    if (objectData != null) {
      if (objectData.getType().equals(PRIVATE_KEY) || objectData.getType().equals(PROTECTED_PRIVATE_KEY)) {
        PrivateKey privateKey = this.privateKeyCache.get(paramString);
        if (privateKey != null)
          return privateKey; 
        EncryptedPrivateKeyData encryptedPrivateKeyData = EncryptedPrivateKeyData.getInstance(objectData.getData());
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(encryptedPrivateKeyData.getEncryptedPrivateKeyInfo());
        try {
          PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(decryptData("PRIVATE_KEY_ENCRYPTION", encryptedPrivateKeyInfo.getEncryptionAlgorithm(), paramArrayOfchar, encryptedPrivateKeyInfo.getEncryptedData()));
          KeyFactory keyFactory = this.helper.createKeyFactory(getPublicKeyAlg(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm()));
          PrivateKey privateKey1 = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded()));
          this.privateKeyCache.put(paramString, privateKey1);
          return privateKey1;
        } catch (Exception exception) {
          throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover private key (" + paramString + "): " + exception.getMessage());
        } 
      } 
      if (objectData.getType().equals(SECRET_KEY) || objectData.getType().equals(PROTECTED_SECRET_KEY)) {
        EncryptedSecretKeyData encryptedSecretKeyData = EncryptedSecretKeyData.getInstance(objectData.getData());
        try {
          SecretKeyData secretKeyData = SecretKeyData.getInstance(decryptData("SECRET_KEY_ENCRYPTION", encryptedSecretKeyData.getKeyEncryptionAlgorithm(), paramArrayOfchar, encryptedSecretKeyData.getEncryptedKeyData()));
          SecretKeyFactory secretKeyFactory = this.helper.createSecretKeyFactory(secretKeyData.getKeyAlgorithm().getId());
          return secretKeyFactory.generateSecret(new SecretKeySpec(secretKeyData.getKeyBytes(), secretKeyData.getKeyAlgorithm().getId()));
        } catch (Exception exception) {
          throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + paramString + "): " + exception.getMessage());
        } 
      } 
      throw new UnrecoverableKeyException("BCFKS KeyStore unable to recover secret key (" + paramString + "): type not recognized");
    } 
    return null;
  }
  
  public Certificate[] engineGetCertificateChain(String paramString) {
    ObjectData objectData = this.entries.get(paramString);
    if (objectData != null && (objectData.getType().equals(PRIVATE_KEY) || objectData.getType().equals(PROTECTED_PRIVATE_KEY))) {
      EncryptedPrivateKeyData encryptedPrivateKeyData = EncryptedPrivateKeyData.getInstance(objectData.getData());
      Certificate[] arrayOfCertificate = encryptedPrivateKeyData.getCertificateChain();
      X509Certificate[] arrayOfX509Certificate = new X509Certificate[arrayOfCertificate.length];
      for (byte b = 0; b != arrayOfX509Certificate.length; b++)
        arrayOfX509Certificate[b] = (X509Certificate)decodeCertificate(arrayOfCertificate[b]); 
      return (Certificate[])arrayOfX509Certificate;
    } 
    return null;
  }
  
  public Certificate engineGetCertificate(String paramString) {
    ObjectData objectData = this.entries.get(paramString);
    if (objectData != null) {
      if (objectData.getType().equals(PRIVATE_KEY) || objectData.getType().equals(PROTECTED_PRIVATE_KEY)) {
        EncryptedPrivateKeyData encryptedPrivateKeyData = EncryptedPrivateKeyData.getInstance(objectData.getData());
        Certificate[] arrayOfCertificate = encryptedPrivateKeyData.getCertificateChain();
        return decodeCertificate(arrayOfCertificate[0]);
      } 
      if (objectData.getType().equals(CERTIFICATE))
        return decodeCertificate(objectData.getData()); 
    } 
    return null;
  }
  
  private Certificate decodeCertificate(Object paramObject) {
    if (this.helper != null)
      try {
        CertificateFactory certificateFactory = this.helper.createCertificateFactory("X.509");
        return certificateFactory.generateCertificate(new ByteArrayInputStream(Certificate.getInstance(paramObject).getEncoded()));
      } catch (Exception exception) {
        return null;
      }  
    try {
      CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
      return certificateFactory.generateCertificate(new ByteArrayInputStream(Certificate.getInstance(paramObject).getEncoded()));
    } catch (Exception exception) {
      return null;
    } 
  }
  
  public Date engineGetCreationDate(String paramString) {
    ObjectData objectData = this.entries.get(paramString);
    if (objectData != null)
      try {
        return objectData.getLastModifiedDate().getDate();
      } catch (ParseException parseException) {
        return new Date();
      }  
    return null;
  }
  
  public void engineSetKeyEntry(String paramString, Key paramKey, char[] paramArrayOfchar, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    Date date1 = new Date();
    Date date2 = date1;
    ObjectData objectData = this.entries.get(paramString);
    if (objectData != null)
      date1 = extractCreationDate(objectData, date1); 
    this.privateKeyCache.remove(paramString);
    if (paramKey instanceof PrivateKey) {
      if (paramArrayOfCertificate == null)
        throw new KeyStoreException("BCFKS KeyStore requires a certificate chain for private key storage."); 
      try {
        EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
        byte[] arrayOfByte1 = paramKey.getEncoded();
        KeyDerivationFunc keyDerivationFunc = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, 32);
        byte[] arrayOfByte2 = generateKey(keyDerivationFunc, "PRIVATE_KEY_ENCRYPTION", (paramArrayOfchar != null) ? paramArrayOfchar : new char[0], 32);
        if (this.storeEncryptionAlgorithm.equals(NISTObjectIdentifiers.id_aes256_CCM)) {
          Cipher cipher = createCipher("AES/CCM/NoPadding", arrayOfByte2);
          byte[] arrayOfByte = cipher.doFinal(arrayOfByte1);
          AlgorithmParameters algorithmParameters = cipher.getParameters();
          PBES2Parameters pBES2Parameters = new PBES2Parameters(keyDerivationFunc, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, CCMParameters.getInstance(algorithmParameters.getEncoded())));
          encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pBES2Parameters), arrayOfByte);
        } else {
          Cipher cipher = createCipher("AESKWP", arrayOfByte2);
          byte[] arrayOfByte = cipher.doFinal(arrayOfByte1);
          PBES2Parameters pBES2Parameters = new PBES2Parameters(keyDerivationFunc, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_wrap_pad));
          encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pBES2Parameters), arrayOfByte);
        } 
        EncryptedPrivateKeyData encryptedPrivateKeyData = createPrivateKeySequence(encryptedPrivateKeyInfo, paramArrayOfCertificate);
        this.entries.put(paramString, new ObjectData(PRIVATE_KEY, paramString, date1, date2, encryptedPrivateKeyData.getEncoded(), null));
      } catch (Exception exception) {
        throw new ExtKeyStoreException("BCFKS KeyStore exception storing private key: " + exception.toString(), exception);
      } 
    } else if (paramKey instanceof javax.crypto.SecretKey) {
      if (paramArrayOfCertificate != null)
        throw new KeyStoreException("BCFKS KeyStore cannot store certificate chain with secret key."); 
      try {
        SecretKeyData secretKeyData;
        EncryptedSecretKeyData encryptedSecretKeyData;
        byte[] arrayOfByte1 = paramKey.getEncoded();
        KeyDerivationFunc keyDerivationFunc = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, 32);
        byte[] arrayOfByte2 = generateKey(keyDerivationFunc, "SECRET_KEY_ENCRYPTION", (paramArrayOfchar != null) ? paramArrayOfchar : new char[0], 32);
        String str = Strings.toUpperCase(paramKey.getAlgorithm());
        if (str.indexOf("AES") > -1) {
          secretKeyData = new SecretKeyData(NISTObjectIdentifiers.aes, arrayOfByte1);
        } else {
          ASN1ObjectIdentifier aSN1ObjectIdentifier = oidMap.get(str);
          if (aSN1ObjectIdentifier != null) {
            secretKeyData = new SecretKeyData(aSN1ObjectIdentifier, arrayOfByte1);
          } else {
            aSN1ObjectIdentifier = oidMap.get(str + "." + (arrayOfByte1.length * 8));
            if (aSN1ObjectIdentifier != null) {
              secretKeyData = new SecretKeyData(aSN1ObjectIdentifier, arrayOfByte1);
            } else {
              throw new KeyStoreException("BCFKS KeyStore cannot recognize secret key (" + str + ") for storage.");
            } 
          } 
        } 
        if (this.storeEncryptionAlgorithm.equals(NISTObjectIdentifiers.id_aes256_CCM)) {
          Cipher cipher = createCipher("AES/CCM/NoPadding", arrayOfByte2);
          byte[] arrayOfByte = cipher.doFinal(secretKeyData.getEncoded());
          AlgorithmParameters algorithmParameters = cipher.getParameters();
          PBES2Parameters pBES2Parameters = new PBES2Parameters(keyDerivationFunc, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, CCMParameters.getInstance(algorithmParameters.getEncoded())));
          encryptedSecretKeyData = new EncryptedSecretKeyData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pBES2Parameters), arrayOfByte);
        } else {
          Cipher cipher = createCipher("AESKWP", arrayOfByte2);
          byte[] arrayOfByte = cipher.doFinal(secretKeyData.getEncoded());
          PBES2Parameters pBES2Parameters = new PBES2Parameters(keyDerivationFunc, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_wrap_pad));
          encryptedSecretKeyData = new EncryptedSecretKeyData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pBES2Parameters), arrayOfByte);
        } 
        this.entries.put(paramString, new ObjectData(SECRET_KEY, paramString, date1, date2, encryptedSecretKeyData.getEncoded(), null));
      } catch (Exception exception) {
        throw new ExtKeyStoreException("BCFKS KeyStore exception storing private key: " + exception.toString(), exception);
      } 
    } else {
      throw new KeyStoreException("BCFKS KeyStore unable to recognize key.");
    } 
    this.lastModifiedDate = date2;
  }
  
  private Cipher createCipher(String paramString, byte[] paramArrayOfbyte) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
    Cipher cipher = this.helper.createCipher(paramString);
    cipher.init(1, new SecretKeySpec(paramArrayOfbyte, "AES"));
    return cipher;
  }
  
  private SecureRandom getDefaultSecureRandom() {
    return CryptoServicesRegistrar.getSecureRandom();
  }
  
  private EncryptedPrivateKeyData createPrivateKeySequence(EncryptedPrivateKeyInfo paramEncryptedPrivateKeyInfo, Certificate[] paramArrayOfCertificate) throws CertificateEncodingException {
    Certificate[] arrayOfCertificate = new Certificate[paramArrayOfCertificate.length];
    for (byte b = 0; b != paramArrayOfCertificate.length; b++)
      arrayOfCertificate[b] = Certificate.getInstance(paramArrayOfCertificate[b].getEncoded()); 
    return new EncryptedPrivateKeyData(paramEncryptedPrivateKeyInfo, arrayOfCertificate);
  }
  
  public void engineSetKeyEntry(String paramString, byte[] paramArrayOfbyte, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    Date date1 = new Date();
    Date date2 = date1;
    ObjectData objectData = this.entries.get(paramString);
    if (objectData != null)
      date1 = extractCreationDate(objectData, date1); 
    if (paramArrayOfCertificate != null) {
      EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
      try {
        encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(paramArrayOfbyte);
      } catch (Exception exception) {
        throw new ExtKeyStoreException("BCFKS KeyStore private key encoding must be an EncryptedPrivateKeyInfo.", exception);
      } 
      try {
        this.privateKeyCache.remove(paramString);
        this.entries.put(paramString, new ObjectData(PROTECTED_PRIVATE_KEY, paramString, date1, date2, createPrivateKeySequence(encryptedPrivateKeyInfo, paramArrayOfCertificate).getEncoded(), null));
      } catch (Exception exception) {
        throw new ExtKeyStoreException("BCFKS KeyStore exception storing protected private key: " + exception.toString(), exception);
      } 
    } else {
      try {
        this.entries.put(paramString, new ObjectData(PROTECTED_SECRET_KEY, paramString, date1, date2, paramArrayOfbyte, null));
      } catch (Exception exception) {
        throw new ExtKeyStoreException("BCFKS KeyStore exception storing protected private key: " + exception.toString(), exception);
      } 
    } 
    this.lastModifiedDate = date2;
  }
  
  public void engineSetCertificateEntry(String paramString, Certificate paramCertificate) throws KeyStoreException {
    ObjectData objectData = this.entries.get(paramString);
    Date date1 = new Date();
    Date date2 = date1;
    if (objectData != null) {
      if (!objectData.getType().equals(CERTIFICATE))
        throw new KeyStoreException("BCFKS KeyStore already has a key entry with alias " + paramString); 
      date1 = extractCreationDate(objectData, date1);
    } 
    try {
      this.entries.put(paramString, new ObjectData(CERTIFICATE, paramString, date1, date2, paramCertificate.getEncoded(), null));
    } catch (CertificateEncodingException certificateEncodingException) {
      throw new ExtKeyStoreException("BCFKS KeyStore unable to handle certificate: " + certificateEncodingException.getMessage(), certificateEncodingException);
    } 
    this.lastModifiedDate = date2;
  }
  
  private Date extractCreationDate(ObjectData paramObjectData, Date paramDate) {
    try {
      paramDate = paramObjectData.getCreationDate().getDate();
    } catch (ParseException parseException) {}
    return paramDate;
  }
  
  public void engineDeleteEntry(String paramString) throws KeyStoreException {
    ObjectData objectData = this.entries.get(paramString);
    if (objectData == null)
      return; 
    this.privateKeyCache.remove(paramString);
    this.entries.remove(paramString);
    this.lastModifiedDate = new Date();
  }
  
  public Enumeration<String> engineAliases() {
    final Iterator<?> it = (new HashSet(this.entries.keySet())).iterator();
    return new Enumeration<String>() {
        public boolean hasMoreElements() {
          return it.hasNext();
        }
        
        public Object nextElement() {
          return it.next();
        }
      };
  }
  
  public boolean engineContainsAlias(String paramString) {
    if (paramString == null)
      throw new NullPointerException("alias value is null"); 
    return this.entries.containsKey(paramString);
  }
  
  public int engineSize() {
    return this.entries.size();
  }
  
  public boolean engineIsKeyEntry(String paramString) {
    ObjectData objectData = this.entries.get(paramString);
    if (objectData != null) {
      BigInteger bigInteger = objectData.getType();
      return (bigInteger.equals(PRIVATE_KEY) || bigInteger.equals(SECRET_KEY) || bigInteger.equals(PROTECTED_PRIVATE_KEY) || bigInteger.equals(PROTECTED_SECRET_KEY));
    } 
    return false;
  }
  
  public boolean engineIsCertificateEntry(String paramString) {
    ObjectData objectData = this.entries.get(paramString);
    return (objectData != null) ? objectData.getType().equals(CERTIFICATE) : false;
  }
  
  public String engineGetCertificateAlias(Certificate paramCertificate) {
    byte[] arrayOfByte;
    if (paramCertificate == null)
      return null; 
    try {
      arrayOfByte = paramCertificate.getEncoded();
    } catch (CertificateEncodingException certificateEncodingException) {
      return null;
    } 
    for (String str : this.entries.keySet()) {
      ObjectData objectData = this.entries.get(str);
      if (objectData.getType().equals(CERTIFICATE)) {
        if (Arrays.areEqual(objectData.getData(), arrayOfByte))
          return str; 
        continue;
      } 
      if (objectData.getType().equals(PRIVATE_KEY) || objectData.getType().equals(PROTECTED_PRIVATE_KEY))
        try {
          EncryptedPrivateKeyData encryptedPrivateKeyData = EncryptedPrivateKeyData.getInstance(objectData.getData());
          if (Arrays.areEqual(encryptedPrivateKeyData.getCertificateChain()[0].toASN1Primitive().getEncoded(), arrayOfByte))
            return str; 
        } catch (IOException iOException) {} 
    } 
    return null;
  }
  
  private byte[] generateKey(KeyDerivationFunc paramKeyDerivationFunc, String paramString, char[] paramArrayOfchar, int paramInt) throws IOException {
    byte[] arrayOfByte1 = PBEParametersGenerator.PKCS12PasswordToBytes(paramArrayOfchar);
    byte[] arrayOfByte2 = PBEParametersGenerator.PKCS12PasswordToBytes(paramString.toCharArray());
    int i = paramInt;
    if (MiscObjectIdentifiers.id_scrypt.equals(paramKeyDerivationFunc.getAlgorithm())) {
      ScryptParams scryptParams = ScryptParams.getInstance(paramKeyDerivationFunc.getParameters());
      if (scryptParams.getKeyLength() != null) {
        i = scryptParams.getKeyLength().intValue();
      } else if (i == -1) {
        throw new IOException("no keyLength found in ScryptParams");
      } 
      return SCrypt.generate(Arrays.concatenate(arrayOfByte1, arrayOfByte2), scryptParams.getSalt(), scryptParams.getCostParameter().intValue(), scryptParams.getBlockSize().intValue(), scryptParams.getBlockSize().intValue(), i);
    } 
    if (paramKeyDerivationFunc.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBKDF2)) {
      PBKDF2Params pBKDF2Params = PBKDF2Params.getInstance(paramKeyDerivationFunc.getParameters());
      if (pBKDF2Params.getKeyLength() != null) {
        i = pBKDF2Params.getKeyLength().intValue();
      } else if (i == -1) {
        throw new IOException("no keyLength found in PBKDF2Params");
      } 
      if (pBKDF2Params.getPrf().getAlgorithm().equals(PKCSObjectIdentifiers.id_hmacWithSHA512)) {
        PKCS5S2ParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator(new SHA512Digest());
        pKCS5S2ParametersGenerator.init(Arrays.concatenate(arrayOfByte1, arrayOfByte2), pBKDF2Params.getSalt(), pBKDF2Params.getIterationCount().intValue());
        return ((KeyParameter)pKCS5S2ParametersGenerator.generateDerivedParameters(i * 8)).getKey();
      } 
      if (pBKDF2Params.getPrf().getAlgorithm().equals(NISTObjectIdentifiers.id_hmacWithSHA3_512)) {
        PKCS5S2ParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator(new SHA3Digest(512));
        pKCS5S2ParametersGenerator.init(Arrays.concatenate(arrayOfByte1, arrayOfByte2), pBKDF2Params.getSalt(), pBKDF2Params.getIterationCount().intValue());
        return ((KeyParameter)pKCS5S2ParametersGenerator.generateDerivedParameters(i * 8)).getKey();
      } 
      throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD PRF: " + pBKDF2Params.getPrf().getAlgorithm());
    } 
    throw new IOException("BCFKS KeyStore: unrecognized MAC PBKD.");
  }
  
  private void verifySig(ASN1Encodable paramASN1Encodable, SignatureCheck paramSignatureCheck, PublicKey paramPublicKey) throws GeneralSecurityException, IOException {
    Signature signature = this.helper.createSignature(paramSignatureCheck.getSignatureAlgorithm().getAlgorithm().getId());
    signature.initVerify(paramPublicKey);
    signature.update(paramASN1Encodable.toASN1Primitive().getEncoded("DER"));
    if (!signature.verify(paramSignatureCheck.getSignature().getOctets()))
      throw new IOException("BCFKS KeyStore corrupted: signature calculation failed"); 
  }
  
  private void verifyMac(byte[] paramArrayOfbyte, PbkdMacIntegrityCheck paramPbkdMacIntegrityCheck, char[] paramArrayOfchar) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    byte[] arrayOfByte = calculateMac(paramArrayOfbyte, paramPbkdMacIntegrityCheck.getMacAlgorithm(), paramPbkdMacIntegrityCheck.getPbkdAlgorithm(), paramArrayOfchar);
    if (!Arrays.constantTimeAreEqual(arrayOfByte, paramPbkdMacIntegrityCheck.getMac()))
      throw new IOException("BCFKS KeyStore corrupted: MAC calculation failed"); 
  }
  
  private byte[] calculateMac(byte[] paramArrayOfbyte, AlgorithmIdentifier paramAlgorithmIdentifier, KeyDerivationFunc paramKeyDerivationFunc, char[] paramArrayOfchar) throws NoSuchAlgorithmException, IOException, NoSuchProviderException {
    String str = paramAlgorithmIdentifier.getAlgorithm().getId();
    Mac mac = this.helper.createMac(str);
    try {
      mac.init(new SecretKeySpec(generateKey(paramKeyDerivationFunc, "INTEGRITY_CHECK", (paramArrayOfchar != null) ? paramArrayOfchar : new char[0], -1), str));
    } catch (InvalidKeyException invalidKeyException) {
      throw new IOException("Cannot set up MAC calculation: " + invalidKeyException.getMessage());
    } 
    return mac.doFinal(paramArrayOfbyte);
  }
  
  public void engineStore(KeyStore.LoadStoreParameter paramLoadStoreParameter) throws CertificateException, NoSuchAlgorithmException, IOException {
    if (paramLoadStoreParameter == null)
      throw new IllegalArgumentException("'parameter' arg cannot be null"); 
    if (paramLoadStoreParameter instanceof BCFKSStoreParameter) {
      BCFKSStoreParameter bCFKSStoreParameter = (BCFKSStoreParameter)paramLoadStoreParameter;
      char[] arrayOfChar = ParameterUtil.extractPassword(paramLoadStoreParameter);
      this.hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bCFKSStoreParameter.getStorePBKDFConfig(), 64);
      engineStore(bCFKSStoreParameter.getOutputStream(), arrayOfChar);
    } else if (paramLoadStoreParameter instanceof BCFKSLoadStoreParameter) {
      BCFKSLoadStoreParameter bCFKSLoadStoreParameter = (BCFKSLoadStoreParameter)paramLoadStoreParameter;
      if (bCFKSLoadStoreParameter.getStoreSignatureKey() != null) {
        this.signatureAlgorithm = generateSignatureAlgId(bCFKSLoadStoreParameter.getStoreSignatureKey(), bCFKSLoadStoreParameter.getStoreSignatureAlgorithm());
        this.hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bCFKSLoadStoreParameter.getStorePBKDFConfig(), 64);
        if (bCFKSLoadStoreParameter.getStoreEncryptionAlgorithm() == BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_CCM) {
          this.storeEncryptionAlgorithm = NISTObjectIdentifiers.id_aes256_CCM;
        } else {
          this.storeEncryptionAlgorithm = NISTObjectIdentifiers.id_aes256_wrap_pad;
        } 
        if (bCFKSLoadStoreParameter.getStoreMacAlgorithm() == BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA512) {
          this.hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);
        } else {
          this.hmacAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_512, DERNull.INSTANCE);
        } 
        char[] arrayOfChar = ParameterUtil.extractPassword(bCFKSLoadStoreParameter);
        EncryptedObjectStoreData encryptedObjectStoreData = getEncryptedObjectStoreData(this.signatureAlgorithm, arrayOfChar);
        try {
          SignatureCheck signatureCheck;
          Signature signature = this.helper.createSignature(this.signatureAlgorithm.getAlgorithm().getId());
          signature.initSign((PrivateKey)bCFKSLoadStoreParameter.getStoreSignatureKey());
          signature.update(encryptedObjectStoreData.getEncoded());
          X509Certificate[] arrayOfX509Certificate = bCFKSLoadStoreParameter.getStoreCertificates();
          if (arrayOfX509Certificate != null) {
            Certificate[] arrayOfCertificate = new Certificate[arrayOfX509Certificate.length];
            for (byte b = 0; b != arrayOfCertificate.length; b++)
              arrayOfCertificate[b] = Certificate.getInstance(arrayOfX509Certificate[b].getEncoded()); 
            signatureCheck = new SignatureCheck(this.signatureAlgorithm, arrayOfCertificate, signature.sign());
          } else {
            signatureCheck = new SignatureCheck(this.signatureAlgorithm, signature.sign());
          } 
          ObjectStore objectStore = new ObjectStore(encryptedObjectStoreData, new ObjectStoreIntegrityCheck(signatureCheck));
          bCFKSLoadStoreParameter.getOutputStream().write(objectStore.getEncoded());
          bCFKSLoadStoreParameter.getOutputStream().flush();
        } catch (GeneralSecurityException generalSecurityException) {
          throw new IOException("error creating signature: " + generalSecurityException.getMessage(), generalSecurityException);
        } 
      } else {
        char[] arrayOfChar = ParameterUtil.extractPassword(bCFKSLoadStoreParameter);
        this.hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bCFKSLoadStoreParameter.getStorePBKDFConfig(), 64);
        if (bCFKSLoadStoreParameter.getStoreEncryptionAlgorithm() == BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_CCM) {
          this.storeEncryptionAlgorithm = NISTObjectIdentifiers.id_aes256_CCM;
        } else {
          this.storeEncryptionAlgorithm = NISTObjectIdentifiers.id_aes256_wrap_pad;
        } 
        if (bCFKSLoadStoreParameter.getStoreMacAlgorithm() == BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA512) {
          this.hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);
        } else {
          this.hmacAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_512, DERNull.INSTANCE);
        } 
        engineStore(bCFKSLoadStoreParameter.getOutputStream(), arrayOfChar);
      } 
    } else if (paramLoadStoreParameter instanceof BCLoadStoreParameter) {
      BCLoadStoreParameter bCLoadStoreParameter = (BCLoadStoreParameter)paramLoadStoreParameter;
      engineStore(bCLoadStoreParameter.getOutputStream(), ParameterUtil.extractPassword(paramLoadStoreParameter));
    } else {
      throw new IllegalArgumentException("no support for 'parameter' of type " + paramLoadStoreParameter.getClass().getName());
    } 
  }
  
  public void engineStore(OutputStream paramOutputStream, char[] paramArrayOfchar) throws IOException, NoSuchAlgorithmException, CertificateException {
    byte[] arrayOfByte;
    if (this.creationDate == null)
      throw new IOException("KeyStore not initialized"); 
    EncryptedObjectStoreData encryptedObjectStoreData = getEncryptedObjectStoreData(this.hmacAlgorithm, paramArrayOfchar);
    if (MiscObjectIdentifiers.id_scrypt.equals(this.hmacPkbdAlgorithm.getAlgorithm())) {
      ScryptParams scryptParams = ScryptParams.getInstance(this.hmacPkbdAlgorithm.getParameters());
      this.hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(this.hmacPkbdAlgorithm, scryptParams.getKeyLength().intValue());
    } else {
      PBKDF2Params pBKDF2Params = PBKDF2Params.getInstance(this.hmacPkbdAlgorithm.getParameters());
      this.hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(this.hmacPkbdAlgorithm, pBKDF2Params.getKeyLength().intValue());
    } 
    try {
      arrayOfByte = calculateMac(encryptedObjectStoreData.getEncoded(), this.hmacAlgorithm, this.hmacPkbdAlgorithm, paramArrayOfchar);
    } catch (NoSuchProviderException noSuchProviderException) {
      throw new IOException("cannot calculate mac: " + noSuchProviderException.getMessage());
    } 
    ObjectStore objectStore = new ObjectStore(encryptedObjectStoreData, new ObjectStoreIntegrityCheck(new PbkdMacIntegrityCheck(this.hmacAlgorithm, this.hmacPkbdAlgorithm, arrayOfByte)));
    paramOutputStream.write(objectStore.getEncoded());
    paramOutputStream.flush();
  }
  
  private EncryptedObjectStoreData getEncryptedObjectStoreData(AlgorithmIdentifier paramAlgorithmIdentifier, char[] paramArrayOfchar) throws IOException, NoSuchAlgorithmException {
    EncryptedObjectStoreData encryptedObjectStoreData;
    ObjectData[] arrayOfObjectData = (ObjectData[])this.entries.values().toArray((Object[])new ObjectData[this.entries.size()]);
    KeyDerivationFunc keyDerivationFunc = generatePkbdAlgorithmIdentifier(this.hmacPkbdAlgorithm, 32);
    byte[] arrayOfByte = generateKey(keyDerivationFunc, "STORE_ENCRYPTION", (paramArrayOfchar != null) ? paramArrayOfchar : new char[0], 32);
    ObjectStoreData objectStoreData = new ObjectStoreData(paramAlgorithmIdentifier, this.creationDate, this.lastModifiedDate, new ObjectDataSequence(arrayOfObjectData), null);
    try {
      if (this.storeEncryptionAlgorithm.equals(NISTObjectIdentifiers.id_aes256_CCM)) {
        Cipher cipher = createCipher("AES/CCM/NoPadding", arrayOfByte);
        byte[] arrayOfByte1 = cipher.doFinal(objectStoreData.getEncoded());
        AlgorithmParameters algorithmParameters = cipher.getParameters();
        PBES2Parameters pBES2Parameters = new PBES2Parameters(keyDerivationFunc, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CCM, CCMParameters.getInstance(algorithmParameters.getEncoded())));
        encryptedObjectStoreData = new EncryptedObjectStoreData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pBES2Parameters), arrayOfByte1);
      } else {
        Cipher cipher = createCipher("AESKWP", arrayOfByte);
        byte[] arrayOfByte1 = cipher.doFinal(objectStoreData.getEncoded());
        PBES2Parameters pBES2Parameters = new PBES2Parameters(keyDerivationFunc, new EncryptionScheme(NISTObjectIdentifiers.id_aes256_wrap_pad));
        encryptedObjectStoreData = new EncryptedObjectStoreData(new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2, pBES2Parameters), arrayOfByte1);
      } 
    } catch (NoSuchPaddingException noSuchPaddingException) {
      throw new NoSuchAlgorithmException(noSuchPaddingException.toString());
    } catch (BadPaddingException badPaddingException) {
      throw new IOException(badPaddingException.toString());
    } catch (IllegalBlockSizeException illegalBlockSizeException) {
      throw new IOException(illegalBlockSizeException.toString());
    } catch (InvalidKeyException invalidKeyException) {
      throw new IOException(invalidKeyException.toString());
    } catch (NoSuchProviderException noSuchProviderException) {
      throw new IOException(noSuchProviderException.toString());
    } 
    return encryptedObjectStoreData;
  }
  
  public void engineLoad(KeyStore.LoadStoreParameter paramLoadStoreParameter) throws CertificateException, NoSuchAlgorithmException, IOException {
    if (paramLoadStoreParameter == null) {
      engineLoad(null, null);
    } else if (paramLoadStoreParameter instanceof BCFKSLoadStoreParameter) {
      BCFKSLoadStoreParameter bCFKSLoadStoreParameter = (BCFKSLoadStoreParameter)paramLoadStoreParameter;
      char[] arrayOfChar = ParameterUtil.extractPassword(bCFKSLoadStoreParameter);
      this.hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(bCFKSLoadStoreParameter.getStorePBKDFConfig(), 64);
      if (bCFKSLoadStoreParameter.getStoreEncryptionAlgorithm() == BCFKSLoadStoreParameter.EncryptionAlgorithm.AES256_CCM) {
        this.storeEncryptionAlgorithm = NISTObjectIdentifiers.id_aes256_CCM;
      } else {
        this.storeEncryptionAlgorithm = NISTObjectIdentifiers.id_aes256_wrap_pad;
      } 
      if (bCFKSLoadStoreParameter.getStoreMacAlgorithm() == BCFKSLoadStoreParameter.MacAlgorithm.HmacSHA512) {
        this.hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);
      } else {
        this.hmacAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.id_hmacWithSHA3_512, DERNull.INSTANCE);
      } 
      this.verificationKey = (PublicKey)bCFKSLoadStoreParameter.getStoreSignatureKey();
      this.validator = bCFKSLoadStoreParameter.getCertChainValidator();
      this.signatureAlgorithm = generateSignatureAlgId(this.verificationKey, bCFKSLoadStoreParameter.getStoreSignatureAlgorithm());
      AlgorithmIdentifier algorithmIdentifier = this.hmacAlgorithm;
      ASN1ObjectIdentifier aSN1ObjectIdentifier = this.storeEncryptionAlgorithm;
      InputStream inputStream = bCFKSLoadStoreParameter.getInputStream();
      engineLoad(inputStream, arrayOfChar);
      if (inputStream != null && (!isSimilarHmacPbkd(bCFKSLoadStoreParameter.getStorePBKDFConfig(), this.hmacPkbdAlgorithm) || !aSN1ObjectIdentifier.equals(this.storeEncryptionAlgorithm)))
        throw new IOException("configuration parameters do not match existing store"); 
    } else if (paramLoadStoreParameter instanceof BCLoadStoreParameter) {
      BCLoadStoreParameter bCLoadStoreParameter = (BCLoadStoreParameter)paramLoadStoreParameter;
      engineLoad(bCLoadStoreParameter.getInputStream(), ParameterUtil.extractPassword(paramLoadStoreParameter));
    } else {
      throw new IllegalArgumentException("no support for 'parameter' of type " + paramLoadStoreParameter.getClass().getName());
    } 
  }
  
  private boolean isSimilarHmacPbkd(PBKDFConfig paramPBKDFConfig, KeyDerivationFunc paramKeyDerivationFunc) {
    if (!paramPBKDFConfig.getAlgorithm().equals(paramKeyDerivationFunc.getAlgorithm()))
      return false; 
    if (MiscObjectIdentifiers.id_scrypt.equals(paramKeyDerivationFunc.getAlgorithm())) {
      if (!(paramPBKDFConfig instanceof ScryptConfig))
        return false; 
      ScryptConfig scryptConfig = (ScryptConfig)paramPBKDFConfig;
      ScryptParams scryptParams = ScryptParams.getInstance(paramKeyDerivationFunc.getParameters());
      if (scryptConfig.getSaltLength() != (scryptParams.getSalt()).length || scryptConfig.getBlockSize() != scryptParams.getBlockSize().intValue() || scryptConfig.getCostParameter() != scryptParams.getCostParameter().intValue() || scryptConfig.getParallelizationParameter() != scryptParams.getParallelizationParameter().intValue())
        return false; 
    } else {
      if (!(paramPBKDFConfig instanceof PBKDF2Config))
        return false; 
      PBKDF2Config pBKDF2Config = (PBKDF2Config)paramPBKDFConfig;
      PBKDF2Params pBKDF2Params = PBKDF2Params.getInstance(paramKeyDerivationFunc.getParameters());
      if (pBKDF2Config.getSaltLength() != (pBKDF2Params.getSalt()).length || pBKDF2Config.getIterationCount() != pBKDF2Params.getIterationCount().intValue())
        return false; 
    } 
    return true;
  }
  
  public void engineLoad(InputStream paramInputStream, char[] paramArrayOfchar) throws IOException, NoSuchAlgorithmException, CertificateException {
    ObjectStore objectStore;
    AlgorithmIdentifier algorithmIdentifier;
    ObjectStoreData objectStoreData;
    this.entries.clear();
    this.privateKeyCache.clear();
    this.lastModifiedDate = this.creationDate = null;
    this.hmacAlgorithm = null;
    if (paramInputStream == null) {
      this.lastModifiedDate = this.creationDate = new Date();
      this.verificationKey = null;
      this.validator = null;
      this.hmacAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE);
      this.hmacPkbdAlgorithm = generatePkbdAlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, 64);
      return;
    } 
    ASN1InputStream aSN1InputStream = new ASN1InputStream(paramInputStream);
    try {
      objectStore = ObjectStore.getInstance(aSN1InputStream.readObject());
    } catch (Exception exception) {
      throw new IOException(exception.getMessage());
    } 
    ObjectStoreIntegrityCheck objectStoreIntegrityCheck = objectStore.getIntegrityCheck();
    if (objectStoreIntegrityCheck.getType() == 0) {
      PbkdMacIntegrityCheck pbkdMacIntegrityCheck = PbkdMacIntegrityCheck.getInstance(objectStoreIntegrityCheck.getIntegrityCheck());
      this.hmacAlgorithm = pbkdMacIntegrityCheck.getMacAlgorithm();
      this.hmacPkbdAlgorithm = pbkdMacIntegrityCheck.getPbkdAlgorithm();
      algorithmIdentifier = this.hmacAlgorithm;
      try {
        verifyMac(objectStore.getStoreData().toASN1Primitive().getEncoded(), pbkdMacIntegrityCheck, paramArrayOfchar);
      } catch (NoSuchProviderException noSuchProviderException) {
        throw new IOException(noSuchProviderException.getMessage());
      } 
    } else if (objectStoreIntegrityCheck.getType() == 1) {
      SignatureCheck signatureCheck = SignatureCheck.getInstance(objectStoreIntegrityCheck.getIntegrityCheck());
      algorithmIdentifier = signatureCheck.getSignatureAlgorithm();
      try {
        Certificate[] arrayOfCertificate = signatureCheck.getCertificates();
        if (this.validator != null) {
          if (arrayOfCertificate == null)
            throw new IOException("validator specified but no certifcates in store"); 
          CertificateFactory certificateFactory = this.helper.createCertificateFactory("X.509");
          X509Certificate[] arrayOfX509Certificate = new X509Certificate[arrayOfCertificate.length];
          for (byte b = 0; b != arrayOfX509Certificate.length; b++)
            arrayOfX509Certificate[b] = (X509Certificate)certificateFactory.generateCertificate(new ByteArrayInputStream(arrayOfCertificate[b].getEncoded())); 
          if (this.validator.isValid(arrayOfX509Certificate)) {
            verifySig(objectStore.getStoreData(), signatureCheck, arrayOfX509Certificate[0].getPublicKey());
          } else {
            throw new IOException("certificate chain in key store signature not valid");
          } 
        } else {
          verifySig(objectStore.getStoreData(), signatureCheck, this.verificationKey);
        } 
      } catch (GeneralSecurityException generalSecurityException) {
        throw new IOException("error verifying signature: " + generalSecurityException.getMessage(), generalSecurityException);
      } 
    } else {
      throw new IOException("BCFKS KeyStore unable to recognize integrity check.");
    } 
    ASN1Encodable aSN1Encodable = objectStore.getStoreData();
    if (aSN1Encodable instanceof EncryptedObjectStoreData) {
      EncryptedObjectStoreData encryptedObjectStoreData = (EncryptedObjectStoreData)aSN1Encodable;
      AlgorithmIdentifier algorithmIdentifier1 = encryptedObjectStoreData.getEncryptionAlgorithm();
      objectStoreData = ObjectStoreData.getInstance(decryptData("STORE_ENCRYPTION", algorithmIdentifier1, paramArrayOfchar, encryptedObjectStoreData.getEncryptedContent().getOctets()));
    } else {
      objectStoreData = ObjectStoreData.getInstance(aSN1Encodable);
    } 
    try {
      this.creationDate = objectStoreData.getCreationDate().getDate();
      this.lastModifiedDate = objectStoreData.getLastModifiedDate().getDate();
    } catch (ParseException parseException) {
      throw new IOException("BCFKS KeyStore unable to parse store data information.");
    } 
    if (!objectStoreData.getIntegrityAlgorithm().equals(algorithmIdentifier))
      throw new IOException("BCFKS KeyStore storeData integrity algorithm does not match store integrity algorithm."); 
    Iterator<ASN1Encodable> iterator = objectStoreData.getObjectDataSequence().iterator();
    while (iterator.hasNext()) {
      ObjectData objectData = ObjectData.getInstance(iterator.next());
      this.entries.put(objectData.getIdentifier(), objectData);
    } 
  }
  
  private byte[] decryptData(String paramString, AlgorithmIdentifier paramAlgorithmIdentifier, char[] paramArrayOfchar, byte[] paramArrayOfbyte) throws IOException {
    if (!paramAlgorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.id_PBES2))
      throw new IOException("BCFKS KeyStore cannot recognize protection algorithm."); 
    PBES2Parameters pBES2Parameters = PBES2Parameters.getInstance(paramAlgorithmIdentifier.getParameters());
    EncryptionScheme encryptionScheme = pBES2Parameters.getEncryptionScheme();
    try {
      Cipher cipher;
      AlgorithmParameters algorithmParameters;
      if (encryptionScheme.getAlgorithm().equals(NISTObjectIdentifiers.id_aes256_CCM)) {
        cipher = this.helper.createCipher("AES/CCM/NoPadding");
        algorithmParameters = this.helper.createAlgorithmParameters("CCM");
        CCMParameters cCMParameters = CCMParameters.getInstance(encryptionScheme.getParameters());
        algorithmParameters.init(cCMParameters.getEncoded());
      } else if (encryptionScheme.getAlgorithm().equals(NISTObjectIdentifiers.id_aes256_wrap_pad)) {
        cipher = this.helper.createCipher("AESKWP");
        algorithmParameters = null;
      } else {
        throw new IOException("BCFKS KeyStore cannot recognize protection encryption algorithm.");
      } 
      byte[] arrayOfByte = generateKey(pBES2Parameters.getKeyDerivationFunc(), paramString, (paramArrayOfchar != null) ? paramArrayOfchar : new char[0], 32);
      cipher.init(2, new SecretKeySpec(arrayOfByte, "AES"), algorithmParameters);
      return cipher.doFinal(paramArrayOfbyte);
    } catch (IOException iOException) {
      throw iOException;
    } catch (Exception exception) {
      throw new IOException(exception.toString());
    } 
  }
  
  private AlgorithmIdentifier generateSignatureAlgId(Key paramKey, BCFKSLoadStoreParameter.SignatureAlgorithm paramSignatureAlgorithm) throws IOException {
    if (paramKey == null)
      return null; 
    if (paramKey instanceof org.bouncycastle.jce.interfaces.ECKey) {
      if (paramSignatureAlgorithm == BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withECDSA)
        return new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA512); 
      if (paramSignatureAlgorithm == BCFKSLoadStoreParameter.SignatureAlgorithm.SHA3_512withECDSA)
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_ecdsa_with_sha3_512); 
    } 
    if (paramKey instanceof java.security.interfaces.DSAKey) {
      if (paramSignatureAlgorithm == BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withDSA)
        return new AlgorithmIdentifier(NISTObjectIdentifiers.dsa_with_sha512); 
      if (paramSignatureAlgorithm == BCFKSLoadStoreParameter.SignatureAlgorithm.SHA3_512withDSA)
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_dsa_with_sha3_512); 
    } 
    if (paramKey instanceof java.security.interfaces.RSAKey) {
      if (paramSignatureAlgorithm == BCFKSLoadStoreParameter.SignatureAlgorithm.SHA512withRSA)
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha512WithRSAEncryption, DERNull.INSTANCE); 
      if (paramSignatureAlgorithm == BCFKSLoadStoreParameter.SignatureAlgorithm.SHA3_512withRSA)
        return new AlgorithmIdentifier(NISTObjectIdentifiers.id_rsassa_pkcs1_v1_5_with_sha3_512, DERNull.INSTANCE); 
    } 
    throw new IOException("unknown signature algorithm");
  }
  
  private KeyDerivationFunc generatePkbdAlgorithmIdentifier(PBKDFConfig paramPBKDFConfig, int paramInt) {
    if (MiscObjectIdentifiers.id_scrypt.equals(paramPBKDFConfig.getAlgorithm())) {
      ScryptConfig scryptConfig = (ScryptConfig)paramPBKDFConfig;
      byte[] arrayOfByte1 = new byte[scryptConfig.getSaltLength()];
      getDefaultSecureRandom().nextBytes(arrayOfByte1);
      ScryptParams scryptParams = new ScryptParams(arrayOfByte1, scryptConfig.getCostParameter(), scryptConfig.getBlockSize(), scryptConfig.getParallelizationParameter(), paramInt);
      return new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt, scryptParams);
    } 
    PBKDF2Config pBKDF2Config = (PBKDF2Config)paramPBKDFConfig;
    byte[] arrayOfByte = new byte[pBKDF2Config.getSaltLength()];
    getDefaultSecureRandom().nextBytes(arrayOfByte);
    return new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(arrayOfByte, pBKDF2Config.getIterationCount(), paramInt, pBKDF2Config.getPRF()));
  }
  
  private KeyDerivationFunc generatePkbdAlgorithmIdentifier(KeyDerivationFunc paramKeyDerivationFunc, int paramInt) {
    if (MiscObjectIdentifiers.id_scrypt.equals(paramKeyDerivationFunc.getAlgorithm())) {
      ScryptParams scryptParams1 = ScryptParams.getInstance(paramKeyDerivationFunc.getParameters());
      byte[] arrayOfByte1 = new byte[(scryptParams1.getSalt()).length];
      getDefaultSecureRandom().nextBytes(arrayOfByte1);
      ScryptParams scryptParams2 = new ScryptParams(arrayOfByte1, scryptParams1.getCostParameter(), scryptParams1.getBlockSize(), scryptParams1.getParallelizationParameter(), BigInteger.valueOf(paramInt));
      return new KeyDerivationFunc(MiscObjectIdentifiers.id_scrypt, scryptParams2);
    } 
    PBKDF2Params pBKDF2Params1 = PBKDF2Params.getInstance(paramKeyDerivationFunc.getParameters());
    byte[] arrayOfByte = new byte[(pBKDF2Params1.getSalt()).length];
    getDefaultSecureRandom().nextBytes(arrayOfByte);
    PBKDF2Params pBKDF2Params2 = new PBKDF2Params(arrayOfByte, pBKDF2Params1.getIterationCount().intValue(), paramInt, pBKDF2Params1.getPrf());
    return new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, pBKDF2Params2);
  }
  
  private KeyDerivationFunc generatePkbdAlgorithmIdentifier(ASN1ObjectIdentifier paramASN1ObjectIdentifier, int paramInt) {
    byte[] arrayOfByte = new byte[64];
    getDefaultSecureRandom().nextBytes(arrayOfByte);
    if (PKCSObjectIdentifiers.id_PBKDF2.equals(paramASN1ObjectIdentifier))
      return new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, new PBKDF2Params(arrayOfByte, 51200, paramInt, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA512, DERNull.INSTANCE))); 
    throw new IllegalStateException("unknown derivation algorithm: " + paramASN1ObjectIdentifier);
  }
  
  static {
    oidMap.put("DESEDE", OIWObjectIdentifiers.desEDE);
    oidMap.put("TRIPLEDES", OIWObjectIdentifiers.desEDE);
    oidMap.put("TDEA", OIWObjectIdentifiers.desEDE);
    oidMap.put("HMACSHA1", PKCSObjectIdentifiers.id_hmacWithSHA1);
    oidMap.put("HMACSHA224", PKCSObjectIdentifiers.id_hmacWithSHA224);
    oidMap.put("HMACSHA256", PKCSObjectIdentifiers.id_hmacWithSHA256);
    oidMap.put("HMACSHA384", PKCSObjectIdentifiers.id_hmacWithSHA384);
    oidMap.put("HMACSHA512", PKCSObjectIdentifiers.id_hmacWithSHA512);
    oidMap.put("SEED", KISAObjectIdentifiers.id_seedCBC);
    oidMap.put("CAMELLIA.128", NTTObjectIdentifiers.id_camellia128_cbc);
    oidMap.put("CAMELLIA.192", NTTObjectIdentifiers.id_camellia192_cbc);
    oidMap.put("CAMELLIA.256", NTTObjectIdentifiers.id_camellia256_cbc);
    oidMap.put("ARIA.128", NSRIObjectIdentifiers.id_aria128_cbc);
    oidMap.put("ARIA.192", NSRIObjectIdentifiers.id_aria192_cbc);
    oidMap.put("ARIA.256", NSRIObjectIdentifiers.id_aria256_cbc);
    publicAlgMap.put(PKCSObjectIdentifiers.rsaEncryption, "RSA");
    publicAlgMap.put(X9ObjectIdentifiers.id_ecPublicKey, "EC");
    publicAlgMap.put(OIWObjectIdentifiers.elGamalAlgorithm, "DH");
    publicAlgMap.put(PKCSObjectIdentifiers.dhKeyAgreement, "DH");
    publicAlgMap.put(X9ObjectIdentifiers.id_dsa, "DSA");
  }
  
  public static class Def extends BcFKSKeyStoreSpi {
    public Def() {
      super(new DefaultJcaJceHelper());
    }
  }
  
  public static class DefCompat extends AdaptingKeyStoreSpi {
    public DefCompat() {
      super(new DefaultJcaJceHelper(), new BcFKSKeyStoreSpi(new DefaultJcaJceHelper()));
    }
  }
  
  public static class DefShared extends SharedKeyStoreSpi {
    public DefShared() {
      super(new DefaultJcaJceHelper());
    }
  }
  
  public static class DefSharedCompat extends AdaptingKeyStoreSpi {
    public DefSharedCompat() {
      super(new DefaultJcaJceHelper(), new BcFKSKeyStoreSpi(new DefaultJcaJceHelper()));
    }
  }
  
  private static class ExtKeyStoreException extends KeyStoreException {
    private final Throwable cause;
    
    ExtKeyStoreException(String param1String, Throwable param1Throwable) {
      super(param1String);
      this.cause = param1Throwable;
    }
    
    public Throwable getCause() {
      return this.cause;
    }
  }
  
  private static class SharedKeyStoreSpi extends BcFKSKeyStoreSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
    private final Map<String, byte[]> cache;
    
    private final byte[] seedKey;
    
    public SharedKeyStoreSpi(JcaJceHelper param1JcaJceHelper) {
      super(param1JcaJceHelper);
      try {
        this.seedKey = new byte[32];
        param1JcaJceHelper.createSecureRandom("DEFAULT").nextBytes(this.seedKey);
      } catch (GeneralSecurityException generalSecurityException) {
        throw new IllegalArgumentException("can't create random - " + generalSecurityException.toString());
      } 
      this.cache = (Map)new HashMap<String, byte>();
    }
    
    public void engineDeleteEntry(String param1String) throws KeyStoreException {
      throw new KeyStoreException("delete operation not supported in shared mode");
    }
    
    public void engineSetKeyEntry(String param1String, Key param1Key, char[] param1ArrayOfchar, Certificate[] param1ArrayOfCertificate) throws KeyStoreException {
      throw new KeyStoreException("set operation not supported in shared mode");
    }
    
    public void engineSetKeyEntry(String param1String, byte[] param1ArrayOfbyte, Certificate[] param1ArrayOfCertificate) throws KeyStoreException {
      throw new KeyStoreException("set operation not supported in shared mode");
    }
    
    public void engineSetCertificateEntry(String param1String, Certificate param1Certificate) throws KeyStoreException {
      throw new KeyStoreException("set operation not supported in shared mode");
    }
    
    public Key engineGetKey(String param1String, char[] param1ArrayOfchar) throws NoSuchAlgorithmException, UnrecoverableKeyException {
      byte[] arrayOfByte;
      try {
        arrayOfByte = calculateMac(param1String, param1ArrayOfchar);
      } catch (InvalidKeyException invalidKeyException) {
        throw new UnrecoverableKeyException("unable to recover key (" + param1String + "): " + invalidKeyException.getMessage());
      } 
      if (this.cache.containsKey(param1String)) {
        byte[] arrayOfByte1 = this.cache.get(param1String);
        if (!Arrays.constantTimeAreEqual(arrayOfByte1, arrayOfByte))
          throw new UnrecoverableKeyException("unable to recover key (" + param1String + ")"); 
      } 
      Key key = super.engineGetKey(param1String, param1ArrayOfchar);
      if (key != null && !this.cache.containsKey(param1String))
        this.cache.put(param1String, arrayOfByte); 
      return key;
    }
    
    private byte[] calculateMac(String param1String, char[] param1ArrayOfchar) throws NoSuchAlgorithmException, InvalidKeyException {
      byte[] arrayOfByte;
      if (param1ArrayOfchar != null) {
        arrayOfByte = Arrays.concatenate(Strings.toUTF8ByteArray(param1ArrayOfchar), Strings.toUTF8ByteArray(param1String));
      } else {
        arrayOfByte = Arrays.concatenate(this.seedKey, Strings.toUTF8ByteArray(param1String));
      } 
      return SCrypt.generate(arrayOfByte, this.seedKey, 16384, 8, 1, 32);
    }
  }
  
  public static class Std extends BcFKSKeyStoreSpi {
    public Std() {
      super(new BCJcaJceHelper());
    }
  }
  
  public static class StdCompat extends AdaptingKeyStoreSpi {
    public StdCompat() {
      super(new DefaultJcaJceHelper(), new BcFKSKeyStoreSpi(new BCJcaJceHelper()));
    }
  }
  
  public static class StdShared extends SharedKeyStoreSpi {
    public StdShared() {
      super(new BCJcaJceHelper());
    }
  }
  
  public static class StdSharedCompat extends AdaptingKeyStoreSpi {
    public StdSharedCompat() {
      super(new BCJcaJceHelper(), new BcFKSKeyStoreSpi(new BCJcaJceHelper()));
    }
  }
}
