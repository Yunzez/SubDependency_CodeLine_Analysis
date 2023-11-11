package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.jcajce.interfaces.XDHPrivateKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

public class BCXDHPrivateKey implements XDHPrivateKey {
  static final long serialVersionUID = 1L;
  
  transient AsymmetricKeyParameter xdhPrivateKey;
  
  private final boolean hasPublicKey = true;
  
  private final byte[] attributes = null;
  
  BCXDHPrivateKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) {
    this.xdhPrivateKey = paramAsymmetricKeyParameter;
  }
  
  BCXDHPrivateKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    populateFromPrivateKeyInfo(paramPrivateKeyInfo);
  }
  
  private void populateFromPrivateKeyInfo(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    byte[] arrayOfByte = paramPrivateKeyInfo.getPrivateKey().getOctets();
    if (arrayOfByte.length != 32 && arrayOfByte.length != 56)
      arrayOfByte = ASN1OctetString.getInstance(paramPrivateKeyInfo.parsePrivateKey()).getOctets(); 
    if (EdECObjectIdentifiers.id_X448.equals(paramPrivateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm())) {
      this.xdhPrivateKey = new X448PrivateKeyParameters(arrayOfByte);
    } else {
      this.xdhPrivateKey = new X25519PrivateKeyParameters(arrayOfByte);
    } 
  }
  
  public String getAlgorithm() {
    return (this.xdhPrivateKey instanceof X448PrivateKeyParameters) ? "X448" : "X25519";
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  public byte[] getEncoded() {
    try {
      ASN1Set aSN1Set = ASN1Set.getInstance(this.attributes);
      PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(this.xdhPrivateKey, aSN1Set);
      return (this.hasPublicKey && !Properties.isOverrideSet("org.bouncycastle.pkcs8.v1_info_only")) ? privateKeyInfo.getEncoded() : (new PrivateKeyInfo(privateKeyInfo.getPrivateKeyAlgorithm(), privateKeyInfo.parsePrivateKey(), aSN1Set)).getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public XDHPublicKey getPublicKey() {
    return (this.xdhPrivateKey instanceof X448PrivateKeyParameters) ? new BCXDHPublicKey(((X448PrivateKeyParameters)this.xdhPrivateKey).generatePublicKey()) : new BCXDHPublicKey(((X25519PrivateKeyParameters)this.xdhPrivateKey).generatePublicKey());
  }
  
  AsymmetricKeyParameter engineGetKeyParameters() {
    return this.xdhPrivateKey;
  }
  
  public String toString() {
    X25519PublicKeyParameters x25519PublicKeyParameters;
    if (this.xdhPrivateKey instanceof X448PrivateKeyParameters) {
      X448PublicKeyParameters x448PublicKeyParameters = ((X448PrivateKeyParameters)this.xdhPrivateKey).generatePublicKey();
    } else {
      x25519PublicKeyParameters = ((X25519PrivateKeyParameters)this.xdhPrivateKey).generatePublicKey();
    } 
    return Utils.keyToString("Private Key", getAlgorithm(), x25519PublicKeyParameters);
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (!(paramObject instanceof PrivateKey))
      return false; 
    PrivateKey privateKey = (PrivateKey)paramObject;
    return Arrays.areEqual(privateKey.getEncoded(), getEncoded());
  }
  
  public int hashCode() {
    return Arrays.hashCode(getEncoded());
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    byte[] arrayOfByte = (byte[])paramObjectInputStream.readObject();
    populateFromPrivateKeyInfo(PrivateKeyInfo.getInstance(arrayOfByte));
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeObject(getEncoded());
  }
}
