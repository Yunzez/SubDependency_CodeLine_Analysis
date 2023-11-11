package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.util.Strings;

public class BCRSAPrivateKey implements RSAPrivateKey, PKCS12BagAttributeCarrier {
  static final long serialVersionUID = 5110188922551353628L;
  
  private static BigInteger ZERO = BigInteger.valueOf(0L);
  
  protected BigInteger modulus;
  
  protected BigInteger privateExponent;
  
  private byte[] algorithmIdentifierEnc = getEncoding(BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER);
  
  protected transient AlgorithmIdentifier algorithmIdentifier = BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER;
  
  protected transient RSAKeyParameters rsaPrivateKey;
  
  protected transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();
  
  BCRSAPrivateKey(RSAKeyParameters paramRSAKeyParameters) {
    this.modulus = paramRSAKeyParameters.getModulus();
    this.privateExponent = paramRSAKeyParameters.getExponent();
    this.rsaPrivateKey = paramRSAKeyParameters;
  }
  
  BCRSAPrivateKey(AlgorithmIdentifier paramAlgorithmIdentifier, RSAKeyParameters paramRSAKeyParameters) {
    this.algorithmIdentifier = paramAlgorithmIdentifier;
    this.algorithmIdentifierEnc = getEncoding(paramAlgorithmIdentifier);
    this.modulus = paramRSAKeyParameters.getModulus();
    this.privateExponent = paramRSAKeyParameters.getExponent();
    this.rsaPrivateKey = paramRSAKeyParameters;
  }
  
  BCRSAPrivateKey(RSAPrivateKeySpec paramRSAPrivateKeySpec) {
    this.modulus = paramRSAPrivateKeySpec.getModulus();
    this.privateExponent = paramRSAPrivateKeySpec.getPrivateExponent();
    this.rsaPrivateKey = new RSAKeyParameters(true, this.modulus, this.privateExponent);
  }
  
  BCRSAPrivateKey(RSAPrivateKey paramRSAPrivateKey) {
    this.modulus = paramRSAPrivateKey.getModulus();
    this.privateExponent = paramRSAPrivateKey.getPrivateExponent();
    this.rsaPrivateKey = new RSAKeyParameters(true, this.modulus, this.privateExponent);
  }
  
  BCRSAPrivateKey(AlgorithmIdentifier paramAlgorithmIdentifier, RSAPrivateKey paramRSAPrivateKey) {
    this.algorithmIdentifier = paramAlgorithmIdentifier;
    this.algorithmIdentifierEnc = getEncoding(paramAlgorithmIdentifier);
    this.modulus = paramRSAPrivateKey.getModulus();
    this.privateExponent = paramRSAPrivateKey.getPrivateExponent();
    this.rsaPrivateKey = new RSAKeyParameters(true, this.modulus, this.privateExponent);
  }
  
  public BigInteger getModulus() {
    return this.modulus;
  }
  
  public BigInteger getPrivateExponent() {
    return this.privateExponent;
  }
  
  public String getAlgorithm() {
    return this.algorithmIdentifier.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS) ? "RSASSA-PSS" : "RSA";
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  RSAKeyParameters engineGetKeyParameters() {
    return this.rsaPrivateKey;
  }
  
  public byte[] getEncoded() {
    return KeyUtil.getEncodedPrivateKeyInfo(this.algorithmIdentifier, new RSAPrivateKey(getModulus(), ZERO, getPrivateExponent(), ZERO, ZERO, ZERO, ZERO, ZERO));
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof RSAPrivateKey))
      return false; 
    if (paramObject == this)
      return true; 
    RSAPrivateKey rSAPrivateKey = (RSAPrivateKey)paramObject;
    return (getModulus().equals(rSAPrivateKey.getModulus()) && getPrivateExponent().equals(rSAPrivateKey.getPrivateExponent()));
  }
  
  public int hashCode() {
    return getModulus().hashCode() ^ getPrivateExponent().hashCode();
  }
  
  public void setBagAttribute(ASN1ObjectIdentifier paramASN1ObjectIdentifier, ASN1Encodable paramASN1Encodable) {
    this.attrCarrier.setBagAttribute(paramASN1ObjectIdentifier, paramASN1Encodable);
  }
  
  public ASN1Encodable getBagAttribute(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return this.attrCarrier.getBagAttribute(paramASN1ObjectIdentifier);
  }
  
  public Enumeration getBagAttributeKeys() {
    return this.attrCarrier.getBagAttributeKeys();
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    if (this.algorithmIdentifierEnc == null)
      this.algorithmIdentifierEnc = getEncoding(BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER); 
    this.algorithmIdentifier = AlgorithmIdentifier.getInstance(this.algorithmIdentifierEnc);
    this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    this.rsaPrivateKey = new RSAKeyParameters(true, this.modulus, this.privateExponent);
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append("RSA Private Key [").append(RSAUtil.generateKeyFingerprint(getModulus())).append("],[]").append(str);
    stringBuffer.append("            modulus: ").append(getModulus().toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  private static byte[] getEncoding(AlgorithmIdentifier paramAlgorithmIdentifier) {
    try {
      return paramAlgorithmIdentifier.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
}
