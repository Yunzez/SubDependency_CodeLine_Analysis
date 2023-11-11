package org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.util.Arrays;

public class BCEdDSAPublicKey implements EdDSAPublicKey {
  static final long serialVersionUID = 1L;
  
  transient AsymmetricKeyParameter eddsaPublicKey;
  
  BCEdDSAPublicKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) {
    this.eddsaPublicKey = paramAsymmetricKeyParameter;
  }
  
  BCEdDSAPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    populateFromPubKeyInfo(paramSubjectPublicKeyInfo);
  }
  
  BCEdDSAPublicKey(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws InvalidKeySpecException {
    int i = paramArrayOfbyte1.length;
    if (Utils.isValidPrefix(paramArrayOfbyte1, paramArrayOfbyte2)) {
      if (paramArrayOfbyte2.length - i == 57) {
        this.eddsaPublicKey = new Ed448PublicKeyParameters(paramArrayOfbyte2, i);
      } else if (paramArrayOfbyte2.length - i == 32) {
        this.eddsaPublicKey = new Ed25519PublicKeyParameters(paramArrayOfbyte2, i);
      } else {
        throw new InvalidKeySpecException("raw key data not recognised");
      } 
    } else {
      throw new InvalidKeySpecException("raw key data not recognised");
    } 
  }
  
  public byte[] getPointEncoding() {
    return (this.eddsaPublicKey instanceof Ed448PublicKeyParameters) ? ((Ed448PublicKeyParameters)this.eddsaPublicKey).getEncoded() : ((Ed25519PublicKeyParameters)this.eddsaPublicKey).getEncoded();
  }
  
  private void populateFromPubKeyInfo(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    byte[] arrayOfByte = paramSubjectPublicKeyInfo.getPublicKeyData().getOctets();
    if (EdECObjectIdentifiers.id_Ed448.equals(paramSubjectPublicKeyInfo.getAlgorithm().getAlgorithm())) {
      this.eddsaPublicKey = new Ed448PublicKeyParameters(arrayOfByte);
    } else {
      this.eddsaPublicKey = new Ed25519PublicKeyParameters(arrayOfByte);
    } 
  }
  
  public String getAlgorithm() {
    return (this.eddsaPublicKey instanceof Ed448PublicKeyParameters) ? "Ed448" : "Ed25519";
  }
  
  public String getFormat() {
    return "X.509";
  }
  
  public byte[] getEncoded() {
    if (this.eddsaPublicKey instanceof Ed448PublicKeyParameters) {
      byte[] arrayOfByte1 = new byte[KeyFactorySpi.Ed448Prefix.length + 57];
      System.arraycopy(KeyFactorySpi.Ed448Prefix, 0, arrayOfByte1, 0, KeyFactorySpi.Ed448Prefix.length);
      ((Ed448PublicKeyParameters)this.eddsaPublicKey).encode(arrayOfByte1, KeyFactorySpi.Ed448Prefix.length);
      return arrayOfByte1;
    } 
    byte[] arrayOfByte = new byte[KeyFactorySpi.Ed25519Prefix.length + 32];
    System.arraycopy(KeyFactorySpi.Ed25519Prefix, 0, arrayOfByte, 0, KeyFactorySpi.Ed25519Prefix.length);
    ((Ed25519PublicKeyParameters)this.eddsaPublicKey).encode(arrayOfByte, KeyFactorySpi.Ed25519Prefix.length);
    return arrayOfByte;
  }
  
  AsymmetricKeyParameter engineGetKeyParameters() {
    return this.eddsaPublicKey;
  }
  
  public String toString() {
    return Utils.keyToString("Public Key", getAlgorithm(), this.eddsaPublicKey);
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
