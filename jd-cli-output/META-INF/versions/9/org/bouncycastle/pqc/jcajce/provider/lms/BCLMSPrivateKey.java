package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.lms;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.lms.HSSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.util.Arrays;

public class BCLMSPrivateKey implements PrivateKey, LMSPrivateKey {
  private static final long serialVersionUID = 8568701712864512338L;
  
  private transient LMSKeyParameters keyParams;
  
  private transient ASN1Set attributes;
  
  public BCLMSPrivateKey(LMSKeyParameters paramLMSKeyParameters) {
    this.keyParams = paramLMSKeyParameters;
  }
  
  public BCLMSPrivateKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    init(paramPrivateKeyInfo);
  }
  
  private void init(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    this.attributes = paramPrivateKeyInfo.getAttributes();
    this.keyParams = (LMSKeyParameters)PrivateKeyFactory.createKey(paramPrivateKeyInfo);
  }
  
  public long getIndex() {
    if (getUsagesRemaining() == 0L)
      throw new IllegalStateException("key exhausted"); 
    if (this.keyParams instanceof LMSPrivateKeyParameters)
      return ((LMSPrivateKeyParameters)this.keyParams).getIndex(); 
    return ((HSSPrivateKeyParameters)this.keyParams).getIndex();
  }
  
  public long getUsagesRemaining() {
    if (this.keyParams instanceof LMSPrivateKeyParameters)
      return ((LMSPrivateKeyParameters)this.keyParams).getUsagesRemaining(); 
    return ((HSSPrivateKeyParameters)this.keyParams).getUsagesRemaining();
  }
  
  public LMSPrivateKey extractKeyShard(int paramInt) {
    if (this.keyParams instanceof LMSPrivateKeyParameters)
      return new org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPrivateKey(((LMSPrivateKeyParameters)this.keyParams).extractKeyShard(paramInt)); 
    return new org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPrivateKey(((HSSPrivateKeyParameters)this.keyParams).extractKeyShard(paramInt));
  }
  
  public String getAlgorithm() {
    return "LMS";
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  public byte[] getEncoded() {
    try {
      PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(this.keyParams, this.attributes);
      return privateKeyInfo.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPrivateKey) {
      org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPrivateKey bCLMSPrivateKey = (org.bouncycastle.pqc.jcajce.provider.lms.BCLMSPrivateKey)paramObject;
      try {
        return Arrays.areEqual(this.keyParams.getEncoded(), bCLMSPrivateKey.keyParams.getEncoded());
      } catch (IOException iOException) {
        throw new IllegalStateException("unable to perform equals");
      } 
    } 
    return false;
  }
  
  public int hashCode() {
    try {
      return Arrays.hashCode(this.keyParams.getEncoded());
    } catch (IOException iOException) {
      throw new IllegalStateException("unable to calculate hashCode");
    } 
  }
  
  CipherParameters getKeyParams() {
    return this.keyParams;
  }
  
  public int getLevels() {
    if (this.keyParams instanceof LMSPrivateKeyParameters)
      return 1; 
    return ((HSSPrivateKeyParameters)this.keyParams).getL();
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    byte[] arrayOfByte = (byte[])paramObjectInputStream.readObject();
    init(PrivateKeyInfo.getInstance(arrayOfByte));
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeObject(getEncoded());
  }
}
