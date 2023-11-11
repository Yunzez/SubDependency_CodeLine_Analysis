package org.bouncycastle.jcajce.provider.asymmetric.ecgost;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECGOST3410Parameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.config.ProviderConfiguration;
import org.bouncycastle.jce.ECGOST3410NamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPointEncoder;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class BCECGOST3410PublicKey implements ECPublicKey, ECPublicKey, ECPointEncoder {
  static final long serialVersionUID = 7026240464295649314L;
  
  private String algorithm = "ECGOST3410";
  
  private boolean withCompression;
  
  private transient ECPublicKeyParameters ecPublicKey;
  
  private transient ECParameterSpec ecSpec;
  
  private transient ASN1Encodable gostParams;
  
  public BCECGOST3410PublicKey(BCECGOST3410PublicKey paramBCECGOST3410PublicKey) {
    this.ecPublicKey = paramBCECGOST3410PublicKey.ecPublicKey;
    this.ecSpec = paramBCECGOST3410PublicKey.ecSpec;
    this.withCompression = paramBCECGOST3410PublicKey.withCompression;
    this.gostParams = paramBCECGOST3410PublicKey.gostParams;
  }
  
  public BCECGOST3410PublicKey(ECPublicKeySpec paramECPublicKeySpec) {
    this.ecSpec = paramECPublicKeySpec.getParams();
    this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(this.ecSpec, paramECPublicKeySpec.getW()), EC5Util.getDomainParameters(null, paramECPublicKeySpec.getParams()));
  }
  
  public BCECGOST3410PublicKey(ECPublicKeySpec paramECPublicKeySpec, ProviderConfiguration paramProviderConfiguration) {
    if (paramECPublicKeySpec.getParams() != null) {
      ECCurve eCCurve = paramECPublicKeySpec.getParams().getCurve();
      EllipticCurve ellipticCurve = EC5Util.convertCurve(eCCurve, paramECPublicKeySpec.getParams().getSeed());
      this.ecPublicKey = new ECPublicKeyParameters(paramECPublicKeySpec.getQ(), ECUtil.getDomainParameters(paramProviderConfiguration, paramECPublicKeySpec.getParams()));
      this.ecSpec = EC5Util.convertSpec(ellipticCurve, paramECPublicKeySpec.getParams());
    } else {
      ECParameterSpec eCParameterSpec = paramProviderConfiguration.getEcImplicitlyCa();
      this.ecPublicKey = new ECPublicKeyParameters(eCParameterSpec.getCurve().createPoint(paramECPublicKeySpec.getQ().getAffineXCoord().toBigInteger(), paramECPublicKeySpec.getQ().getAffineYCoord().toBigInteger()), EC5Util.getDomainParameters(paramProviderConfiguration, (ECParameterSpec)null));
      this.ecSpec = null;
    } 
  }
  
  public BCECGOST3410PublicKey(String paramString, ECPublicKeyParameters paramECPublicKeyParameters, ECParameterSpec paramECParameterSpec) {
    ECDomainParameters eCDomainParameters = paramECPublicKeyParameters.getParameters();
    if (eCDomainParameters instanceof ECGOST3410Parameters) {
      ECGOST3410Parameters eCGOST3410Parameters = (ECGOST3410Parameters)eCDomainParameters;
      this.gostParams = new GOST3410PublicKeyAlgParameters(eCGOST3410Parameters.getPublicKeyParamSet(), eCGOST3410Parameters.getDigestParamSet(), eCGOST3410Parameters.getEncryptionParamSet());
    } 
    this.algorithm = paramString;
    this.ecPublicKey = paramECPublicKeyParameters;
    if (paramECParameterSpec == null) {
      EllipticCurve ellipticCurve = EC5Util.convertCurve(eCDomainParameters.getCurve(), eCDomainParameters.getSeed());
      this.ecSpec = createSpec(ellipticCurve, eCDomainParameters);
    } else {
      this.ecSpec = paramECParameterSpec;
    } 
  }
  
  public BCECGOST3410PublicKey(String paramString, ECPublicKeyParameters paramECPublicKeyParameters, ECParameterSpec paramECParameterSpec) {
    ECDomainParameters eCDomainParameters = paramECPublicKeyParameters.getParameters();
    this.algorithm = paramString;
    this.ecPublicKey = paramECPublicKeyParameters;
    if (paramECParameterSpec == null) {
      EllipticCurve ellipticCurve = EC5Util.convertCurve(eCDomainParameters.getCurve(), eCDomainParameters.getSeed());
      this.ecSpec = createSpec(ellipticCurve, eCDomainParameters);
    } else {
      EllipticCurve ellipticCurve = EC5Util.convertCurve(paramECParameterSpec.getCurve(), paramECParameterSpec.getSeed());
      this.ecSpec = EC5Util.convertSpec(ellipticCurve, paramECParameterSpec);
    } 
  }
  
  public BCECGOST3410PublicKey(String paramString, ECPublicKeyParameters paramECPublicKeyParameters) {
    this.algorithm = paramString;
    this.ecPublicKey = paramECPublicKeyParameters;
    this.ecSpec = null;
  }
  
  private ECParameterSpec createSpec(EllipticCurve paramEllipticCurve, ECDomainParameters paramECDomainParameters) {
    return new ECParameterSpec(paramEllipticCurve, EC5Util.convertPoint(paramECDomainParameters.getG()), paramECDomainParameters.getN(), paramECDomainParameters.getH().intValue());
  }
  
  public BCECGOST3410PublicKey(ECPublicKey paramECPublicKey) {
    this.algorithm = paramECPublicKey.getAlgorithm();
    this.ecSpec = paramECPublicKey.getParams();
    this.ecPublicKey = new ECPublicKeyParameters(EC5Util.convertPoint(this.ecSpec, paramECPublicKey.getW()), EC5Util.getDomainParameters(null, paramECPublicKey.getParams()));
  }
  
  BCECGOST3410PublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    populateFromPubKeyInfo(paramSubjectPublicKeyInfo);
  }
  
  private void populateFromPubKeyInfo(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    ASN1OctetString aSN1OctetString;
    ASN1ObjectIdentifier aSN1ObjectIdentifier;
    ASN1BitString aSN1BitString = paramSubjectPublicKeyInfo.getPublicKeyData();
    this.algorithm = "ECGOST3410";
    try {
      aSN1OctetString = (ASN1OctetString)ASN1Primitive.fromByteArray(aSN1BitString.getBytes());
    } catch (IOException iOException) {
      throw new IllegalArgumentException("error recovering public key");
    } 
    byte[] arrayOfByte1 = aSN1OctetString.getOctets();
    byte[] arrayOfByte2 = new byte[65];
    arrayOfByte2[0] = 4;
    for (byte b = 1; b <= 32; b++) {
      arrayOfByte2[b] = arrayOfByte1[32 - b];
      arrayOfByte2[b + 32] = arrayOfByte1[64 - b];
    } 
    if (paramSubjectPublicKeyInfo.getAlgorithm().getParameters() instanceof ASN1ObjectIdentifier) {
      aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(paramSubjectPublicKeyInfo.getAlgorithm().getParameters());
      this.gostParams = aSN1ObjectIdentifier;
    } else {
      GOST3410PublicKeyAlgParameters gOST3410PublicKeyAlgParameters = GOST3410PublicKeyAlgParameters.getInstance(paramSubjectPublicKeyInfo.getAlgorithm().getParameters());
      this.gostParams = gOST3410PublicKeyAlgParameters;
      aSN1ObjectIdentifier = gOST3410PublicKeyAlgParameters.getPublicKeyParamSet();
    } 
    ECNamedCurveParameterSpec eCNamedCurveParameterSpec = ECGOST3410NamedCurveTable.getParameterSpec(ECGOST3410NamedCurves.getName(aSN1ObjectIdentifier));
    ECCurve eCCurve = eCNamedCurveParameterSpec.getCurve();
    EllipticCurve ellipticCurve = EC5Util.convertCurve(eCCurve, eCNamedCurveParameterSpec.getSeed());
    this.ecPublicKey = new ECPublicKeyParameters(eCCurve.decodePoint(arrayOfByte2), ECUtil.getDomainParameters((ProviderConfiguration)null, eCNamedCurveParameterSpec));
    this.ecSpec = new ECNamedCurveSpec(ECGOST3410NamedCurves.getName(aSN1ObjectIdentifier), ellipticCurve, EC5Util.convertPoint(eCNamedCurveParameterSpec.getG()), eCNamedCurveParameterSpec.getN(), eCNamedCurveParameterSpec.getH());
  }
  
  public String getAlgorithm() {
    return this.algorithm;
  }
  
  public String getFormat() {
    return "X.509";
  }
  
  public byte[] getEncoded() {
    SubjectPublicKeyInfo subjectPublicKeyInfo;
    ASN1Encodable aSN1Encodable = getGostParams();
    if (aSN1Encodable == null)
      if (this.ecSpec instanceof ECNamedCurveSpec) {
        aSN1Encodable = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)this.ecSpec).getName()), CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet);
      } else {
        ECCurve eCCurve = EC5Util.convertCurve(this.ecSpec.getCurve());
        X9ECParameters x9ECParameters = new X9ECParameters(eCCurve, new X9ECPoint(EC5Util.convertPoint(eCCurve, this.ecSpec.getGenerator()), this.withCompression), this.ecSpec.getOrder(), BigInteger.valueOf(this.ecSpec.getCofactor()), this.ecSpec.getCurve().getSeed());
        aSN1Encodable = new X962Parameters(x9ECParameters);
      }  
    BigInteger bigInteger1 = this.ecPublicKey.getQ().getAffineXCoord().toBigInteger();
    BigInteger bigInteger2 = this.ecPublicKey.getQ().getAffineYCoord().toBigInteger();
    byte[] arrayOfByte = new byte[64];
    extractBytes(arrayOfByte, 0, bigInteger1);
    extractBytes(arrayOfByte, 32, bigInteger2);
    try {
      subjectPublicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(CryptoProObjectIdentifiers.gostR3410_2001, aSN1Encodable), new DEROctetString(arrayOfByte));
    } catch (IOException iOException) {
      return null;
    } 
    return KeyUtil.getEncodedSubjectPublicKeyInfo(subjectPublicKeyInfo);
  }
  
  private void extractBytes(byte[] paramArrayOfbyte, int paramInt, BigInteger paramBigInteger) {
    byte[] arrayOfByte = paramBigInteger.toByteArray();
    if (arrayOfByte.length < 32) {
      byte[] arrayOfByte1 = new byte[32];
      System.arraycopy(arrayOfByte, 0, arrayOfByte1, arrayOfByte1.length - arrayOfByte.length, arrayOfByte.length);
      arrayOfByte = arrayOfByte1;
    } 
    for (byte b = 0; b != 32; b++)
      paramArrayOfbyte[paramInt + b] = arrayOfByte[arrayOfByte.length - 1 - b]; 
  }
  
  public ECParameterSpec getParams() {
    return this.ecSpec;
  }
  
  public ECParameterSpec getParameters() {
    return (this.ecSpec == null) ? null : EC5Util.convertSpec(this.ecSpec);
  }
  
  public ECPoint getW() {
    return EC5Util.convertPoint(this.ecPublicKey.getQ());
  }
  
  public ECPoint getQ() {
    return (this.ecSpec == null) ? this.ecPublicKey.getQ().getDetachedPoint() : this.ecPublicKey.getQ();
  }
  
  ECPublicKeyParameters engineGetKeyParameters() {
    return this.ecPublicKey;
  }
  
  ECParameterSpec engineGetSpec() {
    return (this.ecSpec != null) ? EC5Util.convertSpec(this.ecSpec) : BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
  }
  
  public String toString() {
    return ECUtil.publicKeyToString(this.algorithm, this.ecPublicKey.getQ(), engineGetSpec());
  }
  
  public void setPointFormat(String paramString) {
    this.withCompression = !"UNCOMPRESSED".equalsIgnoreCase(paramString);
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof BCECGOST3410PublicKey))
      return false; 
    BCECGOST3410PublicKey bCECGOST3410PublicKey = (BCECGOST3410PublicKey)paramObject;
    return (this.ecPublicKey.getQ().equals(bCECGOST3410PublicKey.ecPublicKey.getQ()) && engineGetSpec().equals(bCECGOST3410PublicKey.engineGetSpec()));
  }
  
  public int hashCode() {
    return this.ecPublicKey.getQ().hashCode() ^ engineGetSpec().hashCode();
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    byte[] arrayOfByte = (byte[])paramObjectInputStream.readObject();
    populateFromPubKeyInfo(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(arrayOfByte)));
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeObject(getEncoded());
  }
  
  ASN1Encodable getGostParams() {
    if (this.gostParams == null && this.ecSpec instanceof ECNamedCurveSpec)
      this.gostParams = new GOST3410PublicKeyAlgParameters(ECGOST3410NamedCurves.getOID(((ECNamedCurveSpec)this.ecSpec).getName()), CryptoProObjectIdentifiers.gostR3411_94_CryptoProParamSet); 
    return this.gostParams;
  }
}
