package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.lms;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyParameters;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;
import org.bouncycastle.pqc.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.LMSKey;
import org.bouncycastle.util.Arrays;

public class BCLMSPublicKey implements PublicKey, LMSKey {
  private static final long serialVersionUID = -5617456225328969766L;
  
  private transient LMSKeyParameters keyParams;
  
  public BCLMSPublicKey(LMSKeyParameters paramLMSKeyParameters) {
    this.keyParams = paramLMSKeyParameters;
  }
  
  public BCLMSPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    init(paramSubjectPublicKeyInfo);
  }
  
  private void init(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    this.keyParams = (LMSKeyParameters)PublicKeyFactory.createKey(paramSubjectPublicKeyInfo);
  }
  
  public final String getAlgorithm() {
    return "LMS";
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
    if (paramObject instanceof org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPublicKey) {
      org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPublicKey bCLMSPublicKey = (org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPublicKey)paramObject;
      try {
        return Arrays.areEqual(this.keyParams.getEncoded(), bCLMSPublicKey.keyParams.getEncoded());
      } catch (IOException iOException) {
        return false;
      } 
    } 
    return false;
  }
  
  public int hashCode() {
    try {
      return Arrays.hashCode(this.keyParams.getEncoded());
    } catch (IOException iOException) {
      return -1;
    } 
  }
  
  public int getLevels() {
    if (this.keyParams instanceof org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters)
      return 1; 
    return ((HSSPublicKeyParameters)this.keyParams).getL();
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
