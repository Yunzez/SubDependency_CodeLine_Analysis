package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.util.Strings;

public class BCRSAPrivateCrtKey extends BCRSAPrivateKey implements RSAPrivateCrtKey {
  static final long serialVersionUID = 7834723820638524718L;
  
  private BigInteger publicExponent;
  
  private BigInteger primeP;
  
  private BigInteger primeQ;
  
  private BigInteger primeExponentP;
  
  private BigInteger primeExponentQ;
  
  private BigInteger crtCoefficient;
  
  BCRSAPrivateCrtKey(RSAPrivateCrtKeyParameters paramRSAPrivateCrtKeyParameters) {
    super(paramRSAPrivateCrtKeyParameters);
    this.publicExponent = paramRSAPrivateCrtKeyParameters.getPublicExponent();
    this.primeP = paramRSAPrivateCrtKeyParameters.getP();
    this.primeQ = paramRSAPrivateCrtKeyParameters.getQ();
    this.primeExponentP = paramRSAPrivateCrtKeyParameters.getDP();
    this.primeExponentQ = paramRSAPrivateCrtKeyParameters.getDQ();
    this.crtCoefficient = paramRSAPrivateCrtKeyParameters.getQInv();
  }
  
  BCRSAPrivateCrtKey(AlgorithmIdentifier paramAlgorithmIdentifier, RSAPrivateCrtKeyParameters paramRSAPrivateCrtKeyParameters) {
    super(paramAlgorithmIdentifier, paramRSAPrivateCrtKeyParameters);
    this.publicExponent = paramRSAPrivateCrtKeyParameters.getPublicExponent();
    this.primeP = paramRSAPrivateCrtKeyParameters.getP();
    this.primeQ = paramRSAPrivateCrtKeyParameters.getQ();
    this.primeExponentP = paramRSAPrivateCrtKeyParameters.getDP();
    this.primeExponentQ = paramRSAPrivateCrtKeyParameters.getDQ();
    this.crtCoefficient = paramRSAPrivateCrtKeyParameters.getQInv();
  }
  
  BCRSAPrivateCrtKey(RSAPrivateCrtKeySpec paramRSAPrivateCrtKeySpec) {
    super(new RSAPrivateCrtKeyParameters(paramRSAPrivateCrtKeySpec.getModulus(), paramRSAPrivateCrtKeySpec.getPublicExponent(), paramRSAPrivateCrtKeySpec.getPrivateExponent(), paramRSAPrivateCrtKeySpec.getPrimeP(), paramRSAPrivateCrtKeySpec.getPrimeQ(), paramRSAPrivateCrtKeySpec.getPrimeExponentP(), paramRSAPrivateCrtKeySpec.getPrimeExponentQ(), paramRSAPrivateCrtKeySpec.getCrtCoefficient()));
    this.modulus = paramRSAPrivateCrtKeySpec.getModulus();
    this.publicExponent = paramRSAPrivateCrtKeySpec.getPublicExponent();
    this.privateExponent = paramRSAPrivateCrtKeySpec.getPrivateExponent();
    this.primeP = paramRSAPrivateCrtKeySpec.getPrimeP();
    this.primeQ = paramRSAPrivateCrtKeySpec.getPrimeQ();
    this.primeExponentP = paramRSAPrivateCrtKeySpec.getPrimeExponentP();
    this.primeExponentQ = paramRSAPrivateCrtKeySpec.getPrimeExponentQ();
    this.crtCoefficient = paramRSAPrivateCrtKeySpec.getCrtCoefficient();
  }
  
  BCRSAPrivateCrtKey(RSAPrivateCrtKey paramRSAPrivateCrtKey) {
    super(new RSAPrivateCrtKeyParameters(paramRSAPrivateCrtKey.getModulus(), paramRSAPrivateCrtKey.getPublicExponent(), paramRSAPrivateCrtKey.getPrivateExponent(), paramRSAPrivateCrtKey.getPrimeP(), paramRSAPrivateCrtKey.getPrimeQ(), paramRSAPrivateCrtKey.getPrimeExponentP(), paramRSAPrivateCrtKey.getPrimeExponentQ(), paramRSAPrivateCrtKey.getCrtCoefficient()));
    this.modulus = paramRSAPrivateCrtKey.getModulus();
    this.publicExponent = paramRSAPrivateCrtKey.getPublicExponent();
    this.privateExponent = paramRSAPrivateCrtKey.getPrivateExponent();
    this.primeP = paramRSAPrivateCrtKey.getPrimeP();
    this.primeQ = paramRSAPrivateCrtKey.getPrimeQ();
    this.primeExponentP = paramRSAPrivateCrtKey.getPrimeExponentP();
    this.primeExponentQ = paramRSAPrivateCrtKey.getPrimeExponentQ();
    this.crtCoefficient = paramRSAPrivateCrtKey.getCrtCoefficient();
  }
  
  BCRSAPrivateCrtKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    this(paramPrivateKeyInfo.getPrivateKeyAlgorithm(), RSAPrivateKey.getInstance(paramPrivateKeyInfo.parsePrivateKey()));
  }
  
  BCRSAPrivateCrtKey(RSAPrivateKey paramRSAPrivateKey) {
    this(BCRSAPublicKey.DEFAULT_ALGORITHM_IDENTIFIER, paramRSAPrivateKey);
  }
  
  BCRSAPrivateCrtKey(AlgorithmIdentifier paramAlgorithmIdentifier, RSAPrivateKey paramRSAPrivateKey) {
    super(paramAlgorithmIdentifier, new RSAPrivateCrtKeyParameters(paramRSAPrivateKey.getModulus(), paramRSAPrivateKey.getPublicExponent(), paramRSAPrivateKey.getPrivateExponent(), paramRSAPrivateKey.getPrime1(), paramRSAPrivateKey.getPrime2(), paramRSAPrivateKey.getExponent1(), paramRSAPrivateKey.getExponent2(), paramRSAPrivateKey.getCoefficient()));
    this.modulus = paramRSAPrivateKey.getModulus();
    this.publicExponent = paramRSAPrivateKey.getPublicExponent();
    this.privateExponent = paramRSAPrivateKey.getPrivateExponent();
    this.primeP = paramRSAPrivateKey.getPrime1();
    this.primeQ = paramRSAPrivateKey.getPrime2();
    this.primeExponentP = paramRSAPrivateKey.getExponent1();
    this.primeExponentQ = paramRSAPrivateKey.getExponent2();
    this.crtCoefficient = paramRSAPrivateKey.getCoefficient();
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  public byte[] getEncoded() {
    return KeyUtil.getEncodedPrivateKeyInfo(this.algorithmIdentifier, new RSAPrivateKey(getModulus(), getPublicExponent(), getPrivateExponent(), getPrimeP(), getPrimeQ(), getPrimeExponentP(), getPrimeExponentQ(), getCrtCoefficient()));
  }
  
  public BigInteger getPublicExponent() {
    return this.publicExponent;
  }
  
  public BigInteger getPrimeP() {
    return this.primeP;
  }
  
  public BigInteger getPrimeQ() {
    return this.primeQ;
  }
  
  public BigInteger getPrimeExponentP() {
    return this.primeExponentP;
  }
  
  public BigInteger getPrimeExponentQ() {
    return this.primeExponentQ;
  }
  
  public BigInteger getCrtCoefficient() {
    return this.crtCoefficient;
  }
  
  public int hashCode() {
    return getModulus().hashCode() ^ getPublicExponent().hashCode() ^ getPrivateExponent().hashCode();
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (!(paramObject instanceof RSAPrivateCrtKey))
      return false; 
    RSAPrivateCrtKey rSAPrivateCrtKey = (RSAPrivateCrtKey)paramObject;
    return (getModulus().equals(rSAPrivateCrtKey.getModulus()) && getPublicExponent().equals(rSAPrivateCrtKey.getPublicExponent()) && getPrivateExponent().equals(rSAPrivateCrtKey.getPrivateExponent()) && getPrimeP().equals(rSAPrivateCrtKey.getPrimeP()) && getPrimeQ().equals(rSAPrivateCrtKey.getPrimeQ()) && getPrimeExponentP().equals(rSAPrivateCrtKey.getPrimeExponentP()) && getPrimeExponentQ().equals(rSAPrivateCrtKey.getPrimeExponentQ()) && getCrtCoefficient().equals(rSAPrivateCrtKey.getCrtCoefficient()));
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    this.rsaPrivateKey = new RSAPrivateCrtKeyParameters(getModulus(), getPublicExponent(), getPrivateExponent(), getPrimeP(), getPrimeQ(), getPrimeExponentP(), getPrimeExponentQ(), getCrtCoefficient());
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append("RSA Private CRT Key [").append(RSAUtil.generateKeyFingerprint(getModulus())).append("]").append(",[").append(RSAUtil.generateExponentFingerprint(getPublicExponent())).append("]").append(str);
    stringBuffer.append("             modulus: ").append(getModulus().toString(16)).append(str);
    stringBuffer.append("     public exponent: ").append(getPublicExponent().toString(16)).append(str);
    return stringBuffer.toString();
  }
}
