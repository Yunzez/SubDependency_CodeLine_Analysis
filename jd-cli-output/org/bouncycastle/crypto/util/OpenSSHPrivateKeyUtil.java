package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

public class OpenSSHPrivateKeyUtil {
  static final byte[] AUTH_MAGIC = Strings.toByteArray("openssh-key-v1\000");
  
  public static byte[] encodePrivateKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) throws IOException {
    if (paramAsymmetricKeyParameter == null)
      throw new IllegalArgumentException("param is null"); 
    if (paramAsymmetricKeyParameter instanceof RSAPrivateCrtKeyParameters) {
      PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(paramAsymmetricKeyParameter);
      return privateKeyInfo.parsePrivateKey().toASN1Primitive().getEncoded();
    } 
    if (paramAsymmetricKeyParameter instanceof ECPrivateKeyParameters) {
      PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(paramAsymmetricKeyParameter);
      return privateKeyInfo.parsePrivateKey().toASN1Primitive().getEncoded();
    } 
    if (paramAsymmetricKeyParameter instanceof DSAPrivateKeyParameters) {
      DSAPrivateKeyParameters dSAPrivateKeyParameters = (DSAPrivateKeyParameters)paramAsymmetricKeyParameter;
      DSAParameters dSAParameters = dSAPrivateKeyParameters.getParameters();
      ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
      aSN1EncodableVector.add(new ASN1Integer(0L));
      aSN1EncodableVector.add(new ASN1Integer(dSAParameters.getP()));
      aSN1EncodableVector.add(new ASN1Integer(dSAParameters.getQ()));
      aSN1EncodableVector.add(new ASN1Integer(dSAParameters.getG()));
      BigInteger bigInteger = dSAParameters.getG().modPow(dSAPrivateKeyParameters.getX(), dSAParameters.getP());
      aSN1EncodableVector.add(new ASN1Integer(bigInteger));
      aSN1EncodableVector.add(new ASN1Integer(dSAPrivateKeyParameters.getX()));
      try {
        return (new DERSequence(aSN1EncodableVector)).getEncoded();
      } catch (Exception exception) {
        throw new IllegalStateException("unable to encode DSAPrivateKeyParameters " + exception.getMessage());
      } 
    } 
    if (paramAsymmetricKeyParameter instanceof Ed25519PrivateKeyParameters) {
      Ed25519PublicKeyParameters ed25519PublicKeyParameters = ((Ed25519PrivateKeyParameters)paramAsymmetricKeyParameter).generatePublicKey();
      SSHBuilder sSHBuilder1 = new SSHBuilder();
      sSHBuilder1.writeBytes(AUTH_MAGIC);
      sSHBuilder1.writeString("none");
      sSHBuilder1.writeString("none");
      sSHBuilder1.writeString("");
      sSHBuilder1.u32(1);
      byte[] arrayOfByte1 = OpenSSHPublicKeyUtil.encodePublicKey(ed25519PublicKeyParameters);
      sSHBuilder1.writeBlock(arrayOfByte1);
      SSHBuilder sSHBuilder2 = new SSHBuilder();
      int i = CryptoServicesRegistrar.getSecureRandom().nextInt();
      sSHBuilder2.u32(i);
      sSHBuilder2.u32(i);
      sSHBuilder2.writeString("ssh-ed25519");
      byte[] arrayOfByte2 = ed25519PublicKeyParameters.getEncoded();
      sSHBuilder2.writeBlock(arrayOfByte2);
      sSHBuilder2.writeBlock(Arrays.concatenate(((Ed25519PrivateKeyParameters)paramAsymmetricKeyParameter).getEncoded(), arrayOfByte2));
      sSHBuilder2.writeString("");
      sSHBuilder1.writeBlock(sSHBuilder2.getPaddedBytes());
      return sSHBuilder1.getBytes();
    } 
    throw new IllegalArgumentException("unable to convert " + paramAsymmetricKeyParameter.getClass().getName() + " to openssh private key");
  }
  
  public static AsymmetricKeyParameter parsePrivateKeyBlob(byte[] paramArrayOfbyte) {
    ECPrivateKeyParameters eCPrivateKeyParameters;
    DSAPrivateKeyParameters dSAPrivateKeyParameters = null;
    if (paramArrayOfbyte[0] == 48) {
      ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(paramArrayOfbyte);
      if (aSN1Sequence.size() == 6) {
        if (allIntegers(aSN1Sequence) && ((ASN1Integer)aSN1Sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO))
          dSAPrivateKeyParameters = new DSAPrivateKeyParameters(((ASN1Integer)aSN1Sequence.getObjectAt(5)).getPositiveValue(), new DSAParameters(((ASN1Integer)aSN1Sequence.getObjectAt(1)).getPositiveValue(), ((ASN1Integer)aSN1Sequence.getObjectAt(2)).getPositiveValue(), ((ASN1Integer)aSN1Sequence.getObjectAt(3)).getPositiveValue())); 
      } else if (aSN1Sequence.size() == 9) {
        if (allIntegers(aSN1Sequence) && ((ASN1Integer)aSN1Sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO)) {
          RSAPrivateKey rSAPrivateKey = RSAPrivateKey.getInstance(aSN1Sequence);
          RSAPrivateCrtKeyParameters rSAPrivateCrtKeyParameters = new RSAPrivateCrtKeyParameters(rSAPrivateKey.getModulus(), rSAPrivateKey.getPublicExponent(), rSAPrivateKey.getPrivateExponent(), rSAPrivateKey.getPrime1(), rSAPrivateKey.getPrime2(), rSAPrivateKey.getExponent1(), rSAPrivateKey.getExponent2(), rSAPrivateKey.getCoefficient());
        } 
      } else if (aSN1Sequence.size() == 4 && aSN1Sequence.getObjectAt(3) instanceof org.bouncycastle.asn1.ASN1TaggedObject && aSN1Sequence.getObjectAt(2) instanceof org.bouncycastle.asn1.ASN1TaggedObject) {
        ECPrivateKey eCPrivateKey = ECPrivateKey.getInstance(aSN1Sequence);
        ASN1ObjectIdentifier aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(eCPrivateKey.getParametersObject());
        X9ECParameters x9ECParameters = ECNamedCurveTable.getByOID(aSN1ObjectIdentifier);
        eCPrivateKeyParameters = new ECPrivateKeyParameters(eCPrivateKey.getKey(), new ECNamedDomainParameters(aSN1ObjectIdentifier, x9ECParameters));
      } 
    } else {
      SSHBuffer sSHBuffer1 = new SSHBuffer(AUTH_MAGIC, paramArrayOfbyte);
      String str1 = sSHBuffer1.readString();
      if (!"none".equals(str1))
        throw new IllegalStateException("encrypted keys not supported"); 
      sSHBuffer1.skipBlock();
      sSHBuffer1.skipBlock();
      int i = sSHBuffer1.readU32();
      if (i != 1)
        throw new IllegalStateException("multiple keys not supported"); 
      OpenSSHPublicKeyUtil.parsePublicKey(sSHBuffer1.readBlock());
      byte[] arrayOfByte = sSHBuffer1.readPaddedBlock();
      if (sSHBuffer1.hasRemaining())
        throw new IllegalArgumentException("decoded key has trailing data"); 
      SSHBuffer sSHBuffer2 = new SSHBuffer(arrayOfByte);
      int j = sSHBuffer2.readU32();
      int k = sSHBuffer2.readU32();
      if (j != k)
        throw new IllegalStateException("private key check values are not the same"); 
      String str2 = sSHBuffer2.readString();
      if ("ssh-ed25519".equals(str2)) {
        sSHBuffer2.readBlock();
        byte[] arrayOfByte1 = sSHBuffer2.readBlock();
        if (arrayOfByte1.length != 64)
          throw new IllegalStateException("private key value of wrong length"); 
        Ed25519PrivateKeyParameters ed25519PrivateKeyParameters = new Ed25519PrivateKeyParameters(arrayOfByte1, 0);
      } else if (str2.startsWith("ecdsa")) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = SSHNamedCurves.getByName(Strings.fromByteArray(sSHBuffer2.readBlock()));
        if (aSN1ObjectIdentifier == null)
          throw new IllegalStateException("OID not found for: " + str2); 
        X9ECParameters x9ECParameters = NISTNamedCurves.getByOID(aSN1ObjectIdentifier);
        if (x9ECParameters == null)
          throw new IllegalStateException("Curve not found for: " + aSN1ObjectIdentifier); 
        sSHBuffer2.readBlock();
        byte[] arrayOfByte1 = sSHBuffer2.readBlock();
        eCPrivateKeyParameters = new ECPrivateKeyParameters(new BigInteger(1, arrayOfByte1), new ECNamedDomainParameters(aSN1ObjectIdentifier, x9ECParameters));
      } 
      sSHBuffer2.skipBlock();
      if (sSHBuffer2.hasRemaining())
        throw new IllegalArgumentException("private key block has trailing data"); 
    } 
    if (eCPrivateKeyParameters == null)
      throw new IllegalArgumentException("unable to parse key"); 
    return eCPrivateKeyParameters;
  }
  
  private static boolean allIntegers(ASN1Sequence paramASN1Sequence) {
    for (byte b = 0; b < paramASN1Sequence.size(); b++) {
      if (!(paramASN1Sequence.getObjectAt(b) instanceof ASN1Integer))
        return false; 
    } 
    return true;
  }
}
