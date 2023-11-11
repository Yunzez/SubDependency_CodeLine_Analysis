package org.bouncycastle.crypto.util;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.SecureRandom;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.util.Encodable;
import org.bouncycastle.util.io.Streams;

public class JournaledAlgorithm implements Encodable, Serializable {
  private transient JournalingSecureRandom journaling;
  
  private transient AlgorithmIdentifier algID;
  
  public JournaledAlgorithm(AlgorithmIdentifier paramAlgorithmIdentifier, JournalingSecureRandom paramJournalingSecureRandom) {
    if (paramAlgorithmIdentifier == null)
      throw new NullPointerException("AlgorithmIdentifier passed to JournaledAlgorithm is null"); 
    if (paramJournalingSecureRandom == null)
      throw new NullPointerException("JournalingSecureRandom passed to JournaledAlgorithm is null"); 
    this.journaling = paramJournalingSecureRandom;
    this.algID = paramAlgorithmIdentifier;
  }
  
  public JournaledAlgorithm(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, CryptoServicesRegistrar.getSecureRandom());
  }
  
  public JournaledAlgorithm(byte[] paramArrayOfbyte, SecureRandom paramSecureRandom) {
    if (paramArrayOfbyte == null)
      throw new NullPointerException("encoding passed to JournaledAlgorithm is null"); 
    if (paramSecureRandom == null)
      throw new NullPointerException("random passed to JournaledAlgorithm is null"); 
    initFromEncoding(paramArrayOfbyte, paramSecureRandom);
  }
  
  private void initFromEncoding(byte[] paramArrayOfbyte, SecureRandom paramSecureRandom) {
    ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(paramArrayOfbyte);
    this.algID = AlgorithmIdentifier.getInstance(aSN1Sequence.getObjectAt(0));
    this.journaling = new JournalingSecureRandom(ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(1)).getOctets(), paramSecureRandom);
  }
  
  public JournalingSecureRandom getJournalingSecureRandom() {
    return this.journaling;
  }
  
  public AlgorithmIdentifier getAlgorithmIdentifier() {
    return this.algID;
  }
  
  public void storeState(File paramFile) throws IOException {
    if (paramFile == null)
      throw new NullPointerException("file for storage is null in JournaledAlgorithm"); 
    FileOutputStream fileOutputStream = new FileOutputStream(paramFile);
    try {
      storeState(fileOutputStream);
    } finally {
      fileOutputStream.close();
    } 
  }
  
  public void storeState(OutputStream paramOutputStream) throws IOException {
    if (paramOutputStream == null)
      throw new NullPointerException("output stream for storage is null in JournaledAlgorithm"); 
    paramOutputStream.write(getEncoded());
  }
  
  public static JournaledAlgorithm getState(InputStream paramInputStream, SecureRandom paramSecureRandom) throws IOException, ClassNotFoundException {
    if (paramInputStream == null)
      throw new NullPointerException("stream for loading is null in JournaledAlgorithm"); 
    BufferedInputStream bufferedInputStream = new BufferedInputStream(paramInputStream);
    try {
      return new JournaledAlgorithm(Streams.readAll(bufferedInputStream), paramSecureRandom);
    } finally {
      bufferedInputStream.close();
    } 
  }
  
  public static JournaledAlgorithm getState(File paramFile, SecureRandom paramSecureRandom) throws IOException, ClassNotFoundException {
    if (paramFile == null)
      throw new NullPointerException("File for loading is null in JournaledAlgorithm"); 
    BufferedInputStream bufferedInputStream = new BufferedInputStream(new FileInputStream(paramFile));
    try {
      return new JournaledAlgorithm(Streams.readAll(bufferedInputStream), paramSecureRandom);
    } finally {
      bufferedInputStream.close();
    } 
  }
  
  public byte[] getEncoded() throws IOException {
    ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
    aSN1EncodableVector.add(this.algID);
    aSN1EncodableVector.add(new DEROctetString(this.journaling.getFullTranscript()));
    return (new DERSequence(aSN1EncodableVector)).getEncoded();
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    initFromEncoding((byte[])paramObjectInputStream.readObject(), CryptoServicesRegistrar.getSecureRandom());
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeObject(getEncoded());
  }
}
