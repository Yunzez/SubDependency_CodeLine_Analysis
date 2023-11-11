package org.bouncycastle.jcajce.provider.keystore.util;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jcajce.BCLoadStoreParameter;
import org.bouncycastle.jcajce.provider.util.DigestFactory;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class JKSKeyStoreSpi extends KeyStoreSpi {
  private static final String NOT_IMPLEMENTED_MESSAGE = "BC JKS store is read-only and only supports certificate entries";
  
  private final Hashtable<String, BCJKSTrustedCertEntry> certificateEntries = new Hashtable<String, BCJKSTrustedCertEntry>();
  
  private final JcaJceHelper helper;
  
  public JKSKeyStoreSpi(JcaJceHelper paramJcaJceHelper) {
    this.helper = paramJcaJceHelper;
  }
  
  public boolean engineProbe(InputStream paramInputStream) throws IOException {
    DataInputStream dataInputStream;
    if (paramInputStream instanceof DataInputStream) {
      dataInputStream = (DataInputStream)paramInputStream;
    } else {
      dataInputStream = new DataInputStream(paramInputStream);
    } 
    int i = dataInputStream.readInt();
    int j = dataInputStream.readInt();
    return (i == -17957139 && (j == 1 || j == 2));
  }
  
  public Key engineGetKey(String paramString, char[] paramArrayOfchar) throws NoSuchAlgorithmException, UnrecoverableKeyException {
    return null;
  }
  
  public Certificate[] engineGetCertificateChain(String paramString) {
    return null;
  }
  
  public Certificate engineGetCertificate(String paramString) {
    synchronized (this.certificateEntries) {
      BCJKSTrustedCertEntry bCJKSTrustedCertEntry = this.certificateEntries.get(paramString);
      if (bCJKSTrustedCertEntry != null)
        return bCJKSTrustedCertEntry.cert; 
    } 
    return null;
  }
  
  public Date engineGetCreationDate(String paramString) {
    synchronized (this.certificateEntries) {
      BCJKSTrustedCertEntry bCJKSTrustedCertEntry = this.certificateEntries.get(paramString);
      if (bCJKSTrustedCertEntry != null)
        return bCJKSTrustedCertEntry.date; 
    } 
    return null;
  }
  
  public void engineSetKeyEntry(String paramString, Key paramKey, char[] paramArrayOfchar, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    throw new KeyStoreException("BC JKS store is read-only and only supports certificate entries");
  }
  
  public void engineSetKeyEntry(String paramString, byte[] paramArrayOfbyte, Certificate[] paramArrayOfCertificate) throws KeyStoreException {
    throw new KeyStoreException("BC JKS store is read-only and only supports certificate entries");
  }
  
  public void engineSetCertificateEntry(String paramString, Certificate paramCertificate) throws KeyStoreException {
    throw new KeyStoreException("BC JKS store is read-only and only supports certificate entries");
  }
  
  public void engineDeleteEntry(String paramString) throws KeyStoreException {
    throw new KeyStoreException("BC JKS store is read-only and only supports certificate entries");
  }
  
  public Enumeration<String> engineAliases() {
    synchronized (this.certificateEntries) {
      return this.certificateEntries.keys();
    } 
  }
  
  public boolean engineContainsAlias(String paramString) {
    if (paramString == null)
      throw new NullPointerException("alias value is null"); 
    synchronized (this.certificateEntries) {
      return this.certificateEntries.containsKey(paramString);
    } 
  }
  
  public int engineSize() {
    return this.certificateEntries.size();
  }
  
  public boolean engineIsKeyEntry(String paramString) {
    return false;
  }
  
  public boolean engineIsCertificateEntry(String paramString) {
    synchronized (this.certificateEntries) {
      return this.certificateEntries.containsKey(paramString);
    } 
  }
  
  public String engineGetCertificateAlias(Certificate paramCertificate) {
    synchronized (this.certificateEntries) {
      for (Map.Entry<String, BCJKSTrustedCertEntry> entry : this.certificateEntries.entrySet()) {
        if (((BCJKSTrustedCertEntry)entry.getValue()).cert.equals(paramCertificate))
          return (String)entry.getKey(); 
      } 
      return null;
    } 
  }
  
  public void engineStore(OutputStream paramOutputStream, char[] paramArrayOfchar) throws IOException, NoSuchAlgorithmException, CertificateException {
    throw new IOException("BC JKS store is read-only and only supports certificate entries");
  }
  
  public void engineLoad(KeyStore.LoadStoreParameter paramLoadStoreParameter) throws IOException, NoSuchAlgorithmException, CertificateException {
    if (paramLoadStoreParameter == null) {
      engineLoad(null, null);
    } else if (paramLoadStoreParameter instanceof BCLoadStoreParameter) {
      BCLoadStoreParameter bCLoadStoreParameter = (BCLoadStoreParameter)paramLoadStoreParameter;
      engineLoad(bCLoadStoreParameter.getInputStream(), ParameterUtil.extractPassword(paramLoadStoreParameter));
    } else {
      throw new IllegalArgumentException("no support for 'param' of type " + paramLoadStoreParameter.getClass().getName());
    } 
  }
  
  public void engineLoad(InputStream paramInputStream, char[] paramArrayOfchar) throws IOException, NoSuchAlgorithmException, CertificateException {
    if (paramInputStream == null)
      return; 
    ErasableByteStream erasableByteStream = validateStream(paramInputStream, paramArrayOfchar);
    synchronized (this.certificateEntries) {
      try {
        DataInputStream dataInputStream = new DataInputStream(erasableByteStream);
        int i = dataInputStream.readInt();
        int j = dataInputStream.readInt();
        if (i == -17957139) {
          CertificateFactory certificateFactory = null;
          Hashtable<Object, Object> hashtable = null;
          switch (j) {
            case 1:
              certificateFactory = createCertFactory("X.509");
              break;
            case 2:
              hashtable = new Hashtable<Object, Object>();
              break;
            default:
              throw new IllegalStateException("unable to discern store version");
          } 
          int k = dataInputStream.readInt();
          for (byte b = 0; b < k; b++) {
            String str;
            Date date;
            int n;
            byte[] arrayOfByte;
            ErasableByteStream erasableByteStream1;
            Certificate certificate;
            int m = dataInputStream.readInt();
            switch (m) {
              case 1:
                throw new IOException("BC JKS store is read-only and only supports certificate entries");
              case 2:
                str = dataInputStream.readUTF();
                date = new Date(dataInputStream.readLong());
                if (j == 2) {
                  String str1 = dataInputStream.readUTF();
                  if (hashtable.containsKey(str1)) {
                    certificateFactory = (CertificateFactory)hashtable.get(str1);
                  } else {
                    certificateFactory = createCertFactory(str1);
                    hashtable.put(str1, certificateFactory);
                  } 
                } 
                n = dataInputStream.readInt();
                arrayOfByte = new byte[n];
                dataInputStream.readFully(arrayOfByte);
                erasableByteStream1 = new ErasableByteStream(arrayOfByte, 0, arrayOfByte.length);
                try {
                  certificate = certificateFactory.generateCertificate(erasableByteStream1);
                  if (erasableByteStream1.available() != 0)
                    throw new IOException("password incorrect or store tampered with"); 
                } finally {
                  erasableByteStream1.erase();
                } 
                this.certificateEntries.put(str, new BCJKSTrustedCertEntry(date, certificate));
                break;
              default:
                throw new IllegalStateException("unable to discern entry type");
            } 
          } 
        } 
        if (erasableByteStream.available() != 0)
          throw new IOException("password incorrect or store tampered with"); 
      } finally {
        erasableByteStream.erase();
      } 
    } 
  }
  
  private CertificateFactory createCertFactory(String paramString) throws CertificateException {
    if (this.helper != null)
      try {
        return this.helper.createCertificateFactory(paramString);
      } catch (NoSuchProviderException noSuchProviderException) {
        throw new CertificateException(noSuchProviderException.toString());
      }  
    return CertificateFactory.getInstance(paramString);
  }
  
  private void addPassword(Digest paramDigest, char[] paramArrayOfchar) throws IOException {
    for (byte b = 0; b < paramArrayOfchar.length; b++) {
      paramDigest.update((byte)(paramArrayOfchar[b] >> 8));
      paramDigest.update((byte)paramArrayOfchar[b]);
    } 
    paramDigest.update(Strings.toByteArray("Mighty Aphrodite"), 0, 16);
  }
  
  private ErasableByteStream validateStream(InputStream paramInputStream, char[] paramArrayOfchar) throws IOException {
    Digest digest = DigestFactory.getDigest("SHA-1");
    byte[] arrayOfByte = Streams.readAll(paramInputStream);
    if (paramArrayOfchar != null) {
      addPassword(digest, paramArrayOfchar);
      digest.update(arrayOfByte, 0, arrayOfByte.length - digest.getDigestSize());
      byte[] arrayOfByte1 = new byte[digest.getDigestSize()];
      digest.doFinal(arrayOfByte1, 0);
      byte[] arrayOfByte2 = new byte[arrayOfByte1.length];
      System.arraycopy(arrayOfByte, arrayOfByte.length - arrayOfByte1.length, arrayOfByte2, 0, arrayOfByte1.length);
      if (!Arrays.constantTimeAreEqual(arrayOfByte1, arrayOfByte2)) {
        Arrays.fill(arrayOfByte, (byte)0);
        throw new IOException("password incorrect or store tampered with");
      } 
      return new ErasableByteStream(arrayOfByte, 0, arrayOfByte.length - arrayOfByte1.length);
    } 
    return new ErasableByteStream(arrayOfByte, 0, arrayOfByte.length - digest.getDigestSize());
  }
  
  private static final class BCJKSTrustedCertEntry {
    final Date date;
    
    final Certificate cert;
    
    public BCJKSTrustedCertEntry(Date param1Date, Certificate param1Certificate) {
      this.date = param1Date;
      this.cert = param1Certificate;
    }
  }
  
  private static final class ErasableByteStream extends ByteArrayInputStream {
    public ErasableByteStream(byte[] param1ArrayOfbyte, int param1Int1, int param1Int2) {
      super(param1ArrayOfbyte, param1Int1, param1Int2);
    }
    
    public void erase() {
      Arrays.fill(this.buf, (byte)0);
    }
  }
}
