package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.math.ec.ECCurve;

public class OpenSSHPublicKeyUtil {
  private static final String RSA = "ssh-rsa";
  
  private static final String ECDSA = "ecdsa";
  
  private static final String ED_25519 = "ssh-ed25519";
  
  private static final String DSS = "ssh-dss";
  
  public static AsymmetricKeyParameter parsePublicKey(byte[] paramArrayOfbyte) {
    SSHBuffer sSHBuffer = new SSHBuffer(paramArrayOfbyte);
    return parsePublicKey(sSHBuffer);
  }
  
  public static byte[] encodePublicKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) throws IOException {
    if (paramAsymmetricKeyParameter == null)
      throw new IllegalArgumentException("cipherParameters was null."); 
    if (paramAsymmetricKeyParameter instanceof RSAKeyParameters) {
      if (paramAsymmetricKeyParameter.isPrivate())
        throw new IllegalArgumentException("RSAKeyParamaters was for encryption"); 
      RSAKeyParameters rSAKeyParameters = (RSAKeyParameters)paramAsymmetricKeyParameter;
      SSHBuilder sSHBuilder = new SSHBuilder();
      sSHBuilder.writeString("ssh-rsa");
      sSHBuilder.writeBigNum(rSAKeyParameters.getExponent());
      sSHBuilder.writeBigNum(rSAKeyParameters.getModulus());
      return sSHBuilder.getBytes();
    } 
    if (paramAsymmetricKeyParameter instanceof ECPublicKeyParameters) {
      SSHBuilder sSHBuilder = new SSHBuilder();
      String str = SSHNamedCurves.getNameForParameters(((ECPublicKeyParameters)paramAsymmetricKeyParameter).getParameters());
      if (str == null)
        throw new IllegalArgumentException("unable to derive ssh curve name for " + ((ECPublicKeyParameters)paramAsymmetricKeyParameter).getParameters().getCurve().getClass().getName()); 
      sSHBuilder.writeString("ecdsa-sha2-" + str);
      sSHBuilder.writeString(str);
      sSHBuilder.writeBlock(((ECPublicKeyParameters)paramAsymmetricKeyParameter).getQ().getEncoded(false));
      return sSHBuilder.getBytes();
    } 
    if (paramAsymmetricKeyParameter instanceof DSAPublicKeyParameters) {
      DSAPublicKeyParameters dSAPublicKeyParameters = (DSAPublicKeyParameters)paramAsymmetricKeyParameter;
      DSAParameters dSAParameters = dSAPublicKeyParameters.getParameters();
      SSHBuilder sSHBuilder = new SSHBuilder();
      sSHBuilder.writeString("ssh-dss");
      sSHBuilder.writeBigNum(dSAParameters.getP());
      sSHBuilder.writeBigNum(dSAParameters.getQ());
      sSHBuilder.writeBigNum(dSAParameters.getG());
      sSHBuilder.writeBigNum(dSAPublicKeyParameters.getY());
      return sSHBuilder.getBytes();
    } 
    if (paramAsymmetricKeyParameter instanceof Ed25519PublicKeyParameters) {
      SSHBuilder sSHBuilder = new SSHBuilder();
      sSHBuilder.writeString("ssh-ed25519");
      sSHBuilder.writeBlock(((Ed25519PublicKeyParameters)paramAsymmetricKeyParameter).getEncoded());
      return sSHBuilder.getBytes();
    } 
    throw new IllegalArgumentException("unable to convert " + paramAsymmetricKeyParameter.getClass().getName() + " to private key");
  }
  
  public static AsymmetricKeyParameter parsePublicKey(SSHBuffer paramSSHBuffer) {
    Ed25519PublicKeyParameters ed25519PublicKeyParameters;
    RSAKeyParameters rSAKeyParameters = null;
    String str = paramSSHBuffer.readString();
    if ("ssh-rsa".equals(str)) {
      BigInteger bigInteger1 = paramSSHBuffer.readBigNumPositive();
      BigInteger bigInteger2 = paramSSHBuffer.readBigNumPositive();
      rSAKeyParameters = new RSAKeyParameters(false, bigInteger2, bigInteger1);
    } else if ("ssh-dss".equals(str)) {
      BigInteger bigInteger1 = paramSSHBuffer.readBigNumPositive();
      BigInteger bigInteger2 = paramSSHBuffer.readBigNumPositive();
      BigInteger bigInteger3 = paramSSHBuffer.readBigNumPositive();
      BigInteger bigInteger4 = paramSSHBuffer.readBigNumPositive();
      DSAPublicKeyParameters dSAPublicKeyParameters = new DSAPublicKeyParameters(bigInteger4, new DSAParameters(bigInteger1, bigInteger2, bigInteger3));
    } else if (str.startsWith("ecdsa")) {
      String str1 = paramSSHBuffer.readString();
      ASN1ObjectIdentifier aSN1ObjectIdentifier = SSHNamedCurves.getByName(str1);
      X9ECParameters x9ECParameters = SSHNamedCurves.getParameters(aSN1ObjectIdentifier);
      if (x9ECParameters == null)
        throw new IllegalStateException("unable to find curve for " + str + " using curve name " + str1); 
      ECCurve eCCurve = x9ECParameters.getCurve();
      byte[] arrayOfByte = paramSSHBuffer.readBlock();
      ECPublicKeyParameters eCPublicKeyParameters = new ECPublicKeyParameters(eCCurve.decodePoint(arrayOfByte), new ECNamedDomainParameters(aSN1ObjectIdentifier, x9ECParameters));
    } else if ("ssh-ed25519".equals(str)) {
      byte[] arrayOfByte = paramSSHBuffer.readBlock();
      if (arrayOfByte.length != 32)
        throw new IllegalStateException("public key value of wrong length"); 
      ed25519PublicKeyParameters = new Ed25519PublicKeyParameters(arrayOfByte, 0);
    } 
    if (ed25519PublicKeyParameters == null)
      throw new IllegalArgumentException("unable to parse key"); 
    if (paramSSHBuffer.hasRemaining())
      throw new IllegalArgumentException("decoded key has trailing data"); 
    return ed25519PublicKeyParameters;
  }
}
