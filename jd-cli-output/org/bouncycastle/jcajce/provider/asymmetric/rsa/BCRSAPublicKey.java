package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.util.Strings;

public class BCRSAPublicKey implements RSAPublicKey {
  static final AlgorithmIdentifier DEFAULT_ALGORITHM_IDENTIFIER = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
  
  static final long serialVersionUID = 2675817738516720772L;
  
  private BigInteger modulus;
  
  private BigInteger publicExponent;
  
  private transient AlgorithmIdentifier algorithmIdentifier;
  
  private transient RSAKeyParameters rsaPublicKey;
  
  BCRSAPublicKey(RSAKeyParameters paramRSAKeyParameters) {
    this(DEFAULT_ALGORITHM_IDENTIFIER, paramRSAKeyParameters);
  }
  
  BCRSAPublicKey(AlgorithmIdentifier paramAlgorithmIdentifier, RSAKeyParameters paramRSAKeyParameters) {
    this.algorithmIdentifier = paramAlgorithmIdentifier;
    this.modulus = paramRSAKeyParameters.getModulus();
    this.publicExponent = paramRSAKeyParameters.getExponent();
    this.rsaPublicKey = paramRSAKeyParameters;
  }
  
  BCRSAPublicKey(RSAPublicKeySpec paramRSAPublicKeySpec) {
    this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
    this.modulus = paramRSAPublicKeySpec.getModulus();
    this.publicExponent = paramRSAPublicKeySpec.getPublicExponent();
    this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
  }
  
  BCRSAPublicKey(RSAPublicKey paramRSAPublicKey) {
    this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
    this.modulus = paramRSAPublicKey.getModulus();
    this.publicExponent = paramRSAPublicKey.getPublicExponent();
    this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
  }
  
  BCRSAPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    populateFromPublicKeyInfo(paramSubjectPublicKeyInfo);
  }
  
  private void populateFromPublicKeyInfo(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    try {
      RSAPublicKey rSAPublicKey = RSAPublicKey.getInstance(paramSubjectPublicKeyInfo.parsePublicKey());
      this.algorithmIdentifier = paramSubjectPublicKeyInfo.getAlgorithm();
      this.modulus = rSAPublicKey.getModulus();
      this.publicExponent = rSAPublicKey.getPublicExponent();
      this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
    } catch (IOException iOException) {
      throw new IllegalArgumentException("invalid info structure in RSA public key");
    } 
  }
  
  public BigInteger getModulus() {
    return this.modulus;
  }
  
  public BigInteger getPublicExponent() {
    return this.publicExponent;
  }
  
  public String getAlgorithm() {
    return this.algorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS) ? "RSASSA-PSS" : "RSA";
  }
  
  public String getFormat() {
    return "X.509";
  }
  
  public byte[] getEncoded() {
    return KeyUtil.getEncodedSubjectPublicKeyInfo(this.algorithmIdentifier, new RSAPublicKey(getModulus(), getPublicExponent()));
  }
  
  RSAKeyParameters engineGetKeyParameters() {
    return this.rsaPublicKey;
  }
  
  public int hashCode() {
    return getModulus().hashCode() ^ getPublicExponent().hashCode();
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (!(paramObject instanceof RSAPublicKey))
      return false; 
    RSAPublicKey rSAPublicKey = (RSAPublicKey)paramObject;
    return (getModulus().equals(rSAPublicKey.getModulus()) && getPublicExponent().equals(rSAPublicKey.getPublicExponent()));
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append("RSA Public Key [").append(RSAUtil.generateKeyFingerprint(getModulus())).append("]").append(",[").append(RSAUtil.generateExponentFingerprint(getPublicExponent())).append("]").append(str);
    stringBuffer.append("        modulus: ").append(getModulus().toString(16)).append(str);
    stringBuffer.append("public exponent: ").append(getPublicExponent().toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    try {
      this.algorithmIdentifier = AlgorithmIdentifier.getInstance(paramObjectInputStream.readObject());
    } catch (Exception exception) {
      this.algorithmIdentifier = DEFAULT_ALGORITHM_IDENTIFIER;
    } 
    this.rsaPublicKey = new RSAKeyParameters(false, this.modulus, this.publicExponent);
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    if (!this.algorithmIdentifier.equals(DEFAULT_ALGORITHM_IDENTIFIER))
      paramObjectOutputStream.writeObject(this.algorithmIdentifier.getEncoded()); 
  }
}
