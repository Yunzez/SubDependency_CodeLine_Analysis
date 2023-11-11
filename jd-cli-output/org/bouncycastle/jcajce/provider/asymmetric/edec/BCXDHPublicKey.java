package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.util.Arrays;

public class BCXDHPublicKey implements XDHPublicKey {
  static final long serialVersionUID = 1L;
  
  transient AsymmetricKeyParameter xdhPublicKey;
  
  BCXDHPublicKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) {
    this.xdhPublicKey = paramAsymmetricKeyParameter;
  }
  
  BCXDHPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    populateFromPubKeyInfo(paramSubjectPublicKeyInfo);
  }
  
  BCXDHPublicKey(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws InvalidKeySpecException {
    int i = paramArrayOfbyte1.length;
    if (Utils.isValidPrefix(paramArrayOfbyte1, paramArrayOfbyte2)) {
      if (paramArrayOfbyte2.length - i == 56) {
        this.xdhPublicKey = new X448PublicKeyParameters(paramArrayOfbyte2, i);
      } else if (paramArrayOfbyte2.length - i == 32) {
        this.xdhPublicKey = new X25519PublicKeyParameters(paramArrayOfbyte2, i);
      } else {
        throw new InvalidKeySpecException("raw key data not recognised");
      } 
    } else {
      throw new InvalidKeySpecException("raw key data not recognised");
    } 
  }
  
  private void populateFromPubKeyInfo(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    byte[] arrayOfByte = paramSubjectPublicKeyInfo.getPublicKeyData().getOctets();
    if (EdECObjectIdentifiers.id_X448.equals(paramSubjectPublicKeyInfo.getAlgorithm().getAlgorithm())) {
      this.xdhPublicKey = new X448PublicKeyParameters(arrayOfByte);
    } else {
      this.xdhPublicKey = new X25519PublicKeyParameters(arrayOfByte);
    } 
  }
  
  public String getAlgorithm() {
    return (this.xdhPublicKey instanceof X448PublicKeyParameters) ? "X448" : "X25519";
  }
  
  public String getFormat() {
    return "X.509";
  }
  
  public byte[] getEncoded() {
    if (this.xdhPublicKey instanceof X448PublicKeyParameters) {
      byte[] arrayOfByte1 = new byte[KeyFactorySpi.x448Prefix.length + 56];
      System.arraycopy(KeyFactorySpi.x448Prefix, 0, arrayOfByte1, 0, KeyFactorySpi.x448Prefix.length);
      ((X448PublicKeyParameters)this.xdhPublicKey).encode(arrayOfByte1, KeyFactorySpi.x448Prefix.length);
      return arrayOfByte1;
    } 
    byte[] arrayOfByte = new byte[KeyFactorySpi.x25519Prefix.length + 32];
    System.arraycopy(KeyFactorySpi.x25519Prefix, 0, arrayOfByte, 0, KeyFactorySpi.x25519Prefix.length);
    ((X25519PublicKeyParameters)this.xdhPublicKey).encode(arrayOfByte, KeyFactorySpi.x25519Prefix.length);
    return arrayOfByte;
  }
  
  AsymmetricKeyParameter engineGetKeyParameters() {
    return this.xdhPublicKey;
  }
  
  public BigInteger getU() {
    byte[] arrayOfByte = getUEncoding();
    Arrays.reverseInPlace(arrayOfByte);
    return new BigInteger(1, arrayOfByte);
  }
  
  public byte[] getUEncoding() {
    return (this.xdhPublicKey instanceof X448PublicKeyParameters) ? ((X448PublicKeyParameters)this.xdhPublicKey).getEncoded() : ((X25519PublicKeyParameters)this.xdhPublicKey).getEncoded();
  }
  
  public String toString() {
    return Utils.keyToString("Public Key", getAlgorithm(), this.xdhPublicKey);
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (!(paramObject instanceof PublicKey))
      return false; 
    PublicKey publicKey = (PublicKey)paramObject;
    return Arrays.areEqual(publicKey.getEncoded(), getEncoded());
  }
  
  public int hashCode() {
    return Arrays.hashCode(getEncoded());
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    byte[] arrayOfByte = (byte[])paramObjectInputStream.readObject();
    populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(arrayOfByte));
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeObject(getEncoded());
  }
}
