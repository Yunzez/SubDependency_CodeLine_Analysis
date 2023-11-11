package org.bouncycastle.pqc.jcajce.provider.qtesla;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.jcajce.interfaces.QTESLAKey;
import org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;
import org.bouncycastle.util.Arrays;

public class BCqTESLAPrivateKey implements PrivateKey, QTESLAKey {
  private static final long serialVersionUID = 1L;
  
  private transient QTESLAPrivateKeyParameters keyParams;
  
  private transient ASN1Set attributes;
  
  public BCqTESLAPrivateKey(QTESLAPrivateKeyParameters paramQTESLAPrivateKeyParameters) {
    this.keyParams = paramQTESLAPrivateKeyParameters;
  }
  
  public BCqTESLAPrivateKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    init(paramPrivateKeyInfo);
  }
  
  private void init(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    this.attributes = paramPrivateKeyInfo.getAttributes();
    this.keyParams = (QTESLAPrivateKeyParameters)PrivateKeyFactory.createKey(paramPrivateKeyInfo);
  }
  
  public final String getAlgorithm() {
    return QTESLASecurityCategory.getName(this.keyParams.getSecurityCategory());
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  public QTESLAParameterSpec getParams() {
    return new QTESLAParameterSpec(getAlgorithm());
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
    if (paramObject instanceof BCqTESLAPrivateKey) {
      BCqTESLAPrivateKey bCqTESLAPrivateKey = (BCqTESLAPrivateKey)paramObject;
      return (this.keyParams.getSecurityCategory() == bCqTESLAPrivateKey.keyParams.getSecurityCategory() && Arrays.areEqual(this.keyParams.getSecret(), bCqTESLAPrivateKey.keyParams.getSecret()));
    } 
    return false;
  }
  
  public int hashCode() {
    return this.keyParams.getSecurityCategory() + 37 * Arrays.hashCode(this.keyParams.getSecret());
  }
  
  CipherParameters getKeyParams() {
    return this.keyParams;
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
