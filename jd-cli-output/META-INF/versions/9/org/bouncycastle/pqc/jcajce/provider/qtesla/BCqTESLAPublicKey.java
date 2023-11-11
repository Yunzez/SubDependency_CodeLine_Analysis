package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.QTESLAKey;
import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCqTESLAPublicKey implements PublicKey, QTESLAKey {
  private static final long serialVersionUID = 1L;
  
  private transient QTESLAPublicKeyParameters keyParams;
  
  public BCqTESLAPublicKey(QTESLAPublicKeyParameters paramQTESLAPublicKeyParameters) {
    this.keyParams = paramQTESLAPublicKeyParameters;
  }
  
  public BCqTESLAPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    init(paramSubjectPublicKeyInfo);
  }
  
  private void init(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    this.keyParams = (QTESLAPublicKeyParameters)PublicKeyFactory.createKey(paramSubjectPublicKeyInfo);
  }
  
  public final String getAlgorithm() {
    return QTESLASecurityCategory.getName(this.keyParams.getSecurityCategory());
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
  
  public QTESLAParameterSpec getParams() {
    return new QTESLAParameterSpec(getAlgorithm());
  }
  
  CipherParameters getKeyParams() {
    return this.keyParams;
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof org.bouncycastle.pqc.jcajce.provider.qtesla.BCqTESLAPublicKey) {
      org.bouncycastle.pqc.jcajce.provider.qtesla.BCqTESLAPublicKey bCqTESLAPublicKey = (org.bouncycastle.pqc.jcajce.provider.qtesla.BCqTESLAPublicKey)paramObject;
      return (this.keyParams.getSecurityCategory() == bCqTESLAPublicKey.keyParams.getSecurityCategory() && 
        Arrays.areEqual(this.keyParams.getPublicData(), bCqTESLAPublicKey.keyParams.getPublicData()));
    } 
    return false;
  }
  
  public int hashCode() {
    return this.keyParams.getSecurityCategory() + 37 * Arrays.hashCode(this.keyParams.getPublicData());
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
