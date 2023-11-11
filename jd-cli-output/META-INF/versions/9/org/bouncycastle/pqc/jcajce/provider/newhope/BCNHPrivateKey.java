package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.newhope;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.NHPrivateKey;
import org.bouncycastle.util.Arrays;

public class BCNHPrivateKey implements NHPrivateKey {
  private static final long serialVersionUID = 1L;
  
  private transient NHPrivateKeyParameters params;
  
  private transient ASN1Set attributes;
  
  public BCNHPrivateKey(NHPrivateKeyParameters paramNHPrivateKeyParameters) {
    this.params = paramNHPrivateKeyParameters;
  }
  
  public BCNHPrivateKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    init(paramPrivateKeyInfo);
  }
  
  private void init(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    this.attributes = paramPrivateKeyInfo.getAttributes();
    this.params = (NHPrivateKeyParameters)PrivateKeyFactory.createKey(paramPrivateKeyInfo);
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof org.bouncycastle.pqc.jcajce.provider.newhope.BCNHPrivateKey))
      return false; 
    org.bouncycastle.pqc.jcajce.provider.newhope.BCNHPrivateKey bCNHPrivateKey = (org.bouncycastle.pqc.jcajce.provider.newhope.BCNHPrivateKey)paramObject;
    return Arrays.areEqual(this.params.getSecData(), bCNHPrivateKey.params.getSecData());
  }
  
  public int hashCode() {
    return Arrays.hashCode(this.params.getSecData());
  }
  
  public final String getAlgorithm() {
    return "NH";
  }
  
  public byte[] getEncoded() {
    try {
      PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(this.params, this.attributes);
      return privateKeyInfo.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  public short[] getSecretData() {
    return this.params.getSecData();
  }
  
  CipherParameters getKeyParams() {
    return this.params;
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
