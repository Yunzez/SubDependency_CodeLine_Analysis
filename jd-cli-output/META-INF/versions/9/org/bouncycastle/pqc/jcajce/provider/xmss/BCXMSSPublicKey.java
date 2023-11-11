package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSKey;
import org.bouncycastle.pqc.jcajce.provider.xmss.DigestUtil;
import org.bouncycastle.util.Arrays;

public class BCXMSSPublicKey implements PublicKey, XMSSKey {
  private static final long serialVersionUID = -5617456225328969766L;
  
  private transient XMSSPublicKeyParameters keyParams;
  
  private transient ASN1ObjectIdentifier treeDigest;
  
  public BCXMSSPublicKey(ASN1ObjectIdentifier paramASN1ObjectIdentifier, XMSSPublicKeyParameters paramXMSSPublicKeyParameters) {
    this.treeDigest = paramASN1ObjectIdentifier;
    this.keyParams = paramXMSSPublicKeyParameters;
  }
  
  public BCXMSSPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    init(paramSubjectPublicKeyInfo);
  }
  
  private void init(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    this.keyParams = (XMSSPublicKeyParameters)PublicKeyFactory.createKey(paramSubjectPublicKeyInfo);
    this.treeDigest = DigestUtil.getDigestOID(this.keyParams.getTreeDigest());
  }
  
  public final String getAlgorithm() {
    return "XMSS";
  }
  
  public byte[] getEncoded() {
    try {
      SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(this.keyParams);
      return subjectPublicKeyInfo.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public String getFormat() {
    return "X.509";
  }
  
  CipherParameters getKeyParams() {
    return this.keyParams;
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPublicKey) {
      org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPublicKey bCXMSSPublicKey = (org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPublicKey)paramObject;
      try {
        return (this.treeDigest.equals(bCXMSSPublicKey.treeDigest) && Arrays.areEqual(this.keyParams.getEncoded(), bCXMSSPublicKey.keyParams.getEncoded()));
      } catch (IOException iOException) {
        return false;
      } 
    } 
    return false;
  }
  
  public int hashCode() {
    try {
      return this.treeDigest.hashCode() + 37 * Arrays.hashCode(this.keyParams.getEncoded());
    } catch (IOException iOException) {
      return this.treeDigest.hashCode();
    } 
  }
  
  public int getHeight() {
    return this.keyParams.getParameters().getHeight();
  }
  
  public String getTreeDigest() {
    return DigestUtil.getXMSSDigestName(this.treeDigest);
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
