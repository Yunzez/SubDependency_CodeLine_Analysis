package org.bouncycastle.jcajce.provider.asymmetric.dstu;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.ua.DSTU4145Params;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.DSAExt;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSTU4145Signer;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;

public class SignatureSpi extends SignatureSpi implements PKCSObjectIdentifiers, X509ObjectIdentifiers {
  private Digest digest;
  
  private DSAExt signer = new DSTU4145Signer();
  
  protected void engineInitVerify(PublicKey paramPublicKey) throws InvalidKeyException {
    AsymmetricKeyParameter asymmetricKeyParameter;
    if (paramPublicKey instanceof BCDSTU4145PublicKey) {
      asymmetricKeyParameter = ((BCDSTU4145PublicKey)paramPublicKey).engineGetKeyParameters();
      this.digest = new GOST3411Digest(expandSbox(((BCDSTU4145PublicKey)paramPublicKey).getSbox()));
    } else {
      asymmetricKeyParameter = ECUtil.generatePublicKeyParameter(paramPublicKey);
      this.digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
    } 
    this.signer.init(false, asymmetricKeyParameter);
  }
  
  byte[] expandSbox(byte[] paramArrayOfbyte) {
    byte[] arrayOfByte = new byte[128];
    for (byte b = 0; b < paramArrayOfbyte.length; b++) {
      arrayOfByte[b * 2] = (byte)(paramArrayOfbyte[b] >> 4 & 0xF);
      arrayOfByte[b * 2 + 1] = (byte)(paramArrayOfbyte[b] & 0xF);
    } 
    return arrayOfByte;
  }
  
  protected void engineInitSign(PrivateKey paramPrivateKey) throws InvalidKeyException {
    AsymmetricKeyParameter asymmetricKeyParameter = null;
    if (paramPrivateKey instanceof BCDSTU4145PrivateKey) {
      asymmetricKeyParameter = ECUtil.generatePrivateKeyParameter(paramPrivateKey);
      this.digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
    } else if (paramPrivateKey instanceof org.bouncycastle.jce.interfaces.ECKey) {
      asymmetricKeyParameter = ECUtil.generatePrivateKeyParameter(paramPrivateKey);
      this.digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
    } 
    if (this.appRandom != null) {
      this.signer.init(true, new ParametersWithRandom(asymmetricKeyParameter, this.appRandom));
    } else {
      this.signer.init(true, asymmetricKeyParameter);
    } 
  }
  
  protected void engineUpdate(byte paramByte) throws SignatureException {
    this.digest.update(paramByte);
  }
  
  protected void engineUpdate(byte[] paramArrayOfbyte, int paramInt1, int paramInt2) throws SignatureException {
    this.digest.update(paramArrayOfbyte, paramInt1, paramInt2);
  }
  
  protected byte[] engineSign() throws SignatureException {
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
    try {
      BigInteger[] arrayOfBigInteger = this.signer.generateSignature(arrayOfByte);
      byte[] arrayOfByte1 = arrayOfBigInteger[0].toByteArray();
      byte[] arrayOfByte2 = arrayOfBigInteger[1].toByteArray();
      byte[] arrayOfByte3 = new byte[(arrayOfByte1.length > arrayOfByte2.length) ? (arrayOfByte1.length * 2) : (arrayOfByte2.length * 2)];
      System.arraycopy(arrayOfByte2, 0, arrayOfByte3, arrayOfByte3.length / 2 - arrayOfByte2.length, arrayOfByte2.length);
      System.arraycopy(arrayOfByte1, 0, arrayOfByte3, arrayOfByte3.length - arrayOfByte1.length, arrayOfByte1.length);
      return (new DEROctetString(arrayOfByte3)).getEncoded();
    } catch (Exception exception) {
      throw new SignatureException(exception.toString());
    } 
  }
  
  protected boolean engineVerify(byte[] paramArrayOfbyte) throws SignatureException {
    BigInteger[] arrayOfBigInteger;
    byte[] arrayOfByte = new byte[this.digest.getDigestSize()];
    this.digest.doFinal(arrayOfByte, 0);
    try {
      byte[] arrayOfByte1 = ((ASN1OctetString)ASN1OctetString.fromByteArray(paramArrayOfbyte)).getOctets();
      byte[] arrayOfByte2 = new byte[arrayOfByte1.length / 2];
      byte[] arrayOfByte3 = new byte[arrayOfByte1.length / 2];
      System.arraycopy(arrayOfByte1, 0, arrayOfByte3, 0, arrayOfByte1.length / 2);
      System.arraycopy(arrayOfByte1, arrayOfByte1.length / 2, arrayOfByte2, 0, arrayOfByte1.length / 2);
      arrayOfBigInteger = new BigInteger[2];
      arrayOfBigInteger[0] = new BigInteger(1, arrayOfByte2);
      arrayOfBigInteger[1] = new BigInteger(1, arrayOfByte3);
    } catch (Exception exception) {
      throw new SignatureException("error decoding signature bytes.");
    } 
    return this.signer.verifySignature(arrayOfByte, arrayOfBigInteger[0], arrayOfBigInteger[1]);
  }
  
  protected void engineSetParameter(AlgorithmParameterSpec paramAlgorithmParameterSpec) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
  
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }
  
  protected void engineSetParameter(String paramString, Object paramObject) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
  
  protected Object engineGetParameter(String paramString) {
    throw new UnsupportedOperationException("engineSetParameter unsupported");
  }
}
