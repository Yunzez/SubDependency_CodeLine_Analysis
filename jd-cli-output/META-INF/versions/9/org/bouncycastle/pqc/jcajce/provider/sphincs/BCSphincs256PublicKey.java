package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.sphincs;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.SPHINCSKey;
import org.bouncycastle.util.Arrays;

public class BCSphincs256PublicKey implements PublicKey, SPHINCSKey {
  private static final long serialVersionUID = 1L;
  
  private transient ASN1ObjectIdentifier treeDigest;
  
  private transient SPHINCSPublicKeyParameters params;
  
  public BCSphincs256PublicKey(ASN1ObjectIdentifier paramASN1ObjectIdentifier, SPHINCSPublicKeyParameters paramSPHINCSPublicKeyParameters) {
    this.treeDigest = paramASN1ObjectIdentifier;
    this.params = paramSPHINCSPublicKeyParameters;
  }
  
  public BCSphincs256PublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    init(paramSubjectPublicKeyInfo);
  }
  
  private void init(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    this.treeDigest = SPHINCS256KeyParams.getInstance(paramSubjectPublicKeyInfo.getAlgorithm().getParameters()).getTreeDigest().getAlgorithm();
    this.params = (SPHINCSPublicKeyParameters)PublicKeyFactory.createKey(paramSubjectPublicKeyInfo);
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof org.bouncycastle.pqc.jcajce.provider.sphincs.BCSphincs256PublicKey) {
      org.bouncycastle.pqc.jcajce.provider.sphincs.BCSphincs256PublicKey bCSphincs256PublicKey = (org.bouncycastle.pqc.jcajce.provider.sphincs.BCSphincs256PublicKey)paramObject;
      return (this.treeDigest.equals(bCSphincs256PublicKey.treeDigest) && Arrays.areEqual(this.params.getKeyData(), bCSphincs256PublicKey.params.getKeyData()));
    } 
    return false;
  }
  
  public int hashCode() {
    return this.treeDigest.hashCode() + 37 * Arrays.hashCode(this.params.getKeyData());
  }
  
  public final String getAlgorithm() {
    return "SPHINCS-256";
  }
  
  public byte[] getEncoded() {
    try {
      SubjectPublicKeyInfo subjectPublicKeyInfo;
      if (this.params.getTreeDigest() != null) {
        subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.params);
      } else {
        AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.sphincs256, new SPHINCS256KeyParams(new AlgorithmIdentifier(this.treeDigest)));
        subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, this.params.getKeyData());
      } 
      return subjectPublicKeyInfo.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public String getFormat() {
    return "X.509";
  }
  
  public byte[] getKeyData() {
    return this.params.getKeyData();
  }
  
  ASN1ObjectIdentifier getTreeDigest() {
    return this.treeDigest;
  }
  
  CipherParameters getKeyParams() {
    return this.params;
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    byte[] arrayOfByte = (byte[])paramObjectInputStream.readObject();
    init(SubjectPublicKeyInfo.getInstance(arrayOfByte));
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeObject(getEncoded());
  }
}
