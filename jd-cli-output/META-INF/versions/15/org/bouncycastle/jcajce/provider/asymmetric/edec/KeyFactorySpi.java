package META-INF.versions.15.org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil;
import org.bouncycastle.jcajce.interfaces.EdDSAPublicKey;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC11XDHPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC11XDHPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC15EdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC15EdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;
import org.bouncycastle.jcajce.spec.OpenSSHPrivateKeySpec;
import org.bouncycastle.jcajce.spec.OpenSSHPublicKeySpec;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class KeyFactorySpi extends BaseKeyFactorySpi implements AsymmetricKeyInfoConverter {
  static final byte[] x448Prefix = Hex.decode("3042300506032b656f033900");
  
  static final byte[] x25519Prefix = Hex.decode("302a300506032b656e032100");
  
  static final byte[] Ed448Prefix = Hex.decode("3043300506032b6571033a00");
  
  static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");
  
  private static final byte x448_type = 111;
  
  private static final byte x25519_type = 110;
  
  private static final byte Ed448_type = 113;
  
  private static final byte Ed25519_type = 112;
  
  String algorithm;
  
  private final boolean isXdh;
  
  private final int specificBase;
  
  public KeyFactorySpi(String paramString, boolean paramBoolean, int paramInt) {
    this.algorithm = paramString;
    this.isXdh = paramBoolean;
    this.specificBase = paramInt;
  }
  
  protected Key engineTranslateKey(Key paramKey) throws InvalidKeyException {
    throw new InvalidKeyException("key type unknown");
  }
  
  protected KeySpec engineGetKeySpec(Key paramKey, Class paramClass) throws InvalidKeySpecException {
    if (paramClass.isAssignableFrom(OpenSSHPrivateKeySpec.class) && paramKey instanceof BC15EdDSAPrivateKey)
      try {
        ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(paramKey.getEncoded());
        ASN1OctetString aSN1OctetString = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(2));
        byte[] arrayOfByte = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(aSN1OctetString.getOctets())).getOctets();
        return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new Ed25519PrivateKeyParameters(arrayOfByte)));
      } catch (IOException iOException) {
        throw new InvalidKeySpecException(iOException.getMessage(), iOException.getCause());
      }  
    if (paramClass.isAssignableFrom(OpenSSHPublicKeySpec.class) && paramKey instanceof BC15EdDSAPublicKey)
      try {
        byte[] arrayOfByte = paramKey.getEncoded();
        if (!Arrays.areEqual(Ed25519Prefix, 0, Ed25519Prefix.length, arrayOfByte, 0, arrayOfByte.length - 32))
          throw new InvalidKeySpecException("Invalid Ed25519 public key encoding"); 
        Ed25519PublicKeyParameters ed25519PublicKeyParameters = new Ed25519PublicKeyParameters(arrayOfByte, Ed25519Prefix.length);
        return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(ed25519PublicKeyParameters));
      } catch (IOException iOException) {
        throw new InvalidKeySpecException(iOException.getMessage(), iOException.getCause());
      }  
    if (paramClass.isAssignableFrom(RawEncodedKeySpec.class)) {
      if (paramKey instanceof XDHPublicKey)
        return new RawEncodedKeySpec(((XDHPublicKey)paramKey).getUEncoding()); 
      if (paramKey instanceof EdDSAPublicKey)
        return new RawEncodedKeySpec(((EdDSAPublicKey)paramKey).getPointEncoding()); 
    } 
    return super.engineGetKeySpec(paramKey, paramClass);
  }
  
  protected PrivateKey engineGeneratePrivate(KeySpec paramKeySpec) throws InvalidKeySpecException {
    if (paramKeySpec instanceof OpenSSHPrivateKeySpec) {
      AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)paramKeySpec).getEncoded());
      if (asymmetricKeyParameter instanceof Ed25519PrivateKeyParameters)
        return (PrivateKey)new BC15EdDSAPrivateKey(asymmetricKeyParameter); 
      throw new IllegalStateException("openssh private key not Ed25519 private key");
    } 
    return super.engineGeneratePrivate(paramKeySpec);
  }
  
  protected PublicKey engineGeneratePublic(KeySpec paramKeySpec) throws InvalidKeySpecException {
    if (paramKeySpec instanceof X509EncodedKeySpec) {
      byte[] arrayOfByte = ((X509EncodedKeySpec)paramKeySpec).getEncoded();
      if (this.specificBase == 0 || this.specificBase == arrayOfByte[8]) {
        if (arrayOfByte[9] == 5 && arrayOfByte[10] == 0) {
          SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(arrayOfByte);
          subjectPublicKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(subjectPublicKeyInfo.getAlgorithm().getAlgorithm()), subjectPublicKeyInfo.getPublicKeyData().getBytes());
          try {
            arrayOfByte = subjectPublicKeyInfo.getEncoded("DER");
          } catch (IOException iOException) {
            throw new InvalidKeySpecException("attempt to reconstruct key failed: " + iOException.getMessage());
          } 
        } 
        switch (arrayOfByte[8]) {
          case 111:
            return (PublicKey)new BC11XDHPublicKey(x448Prefix, arrayOfByte);
          case 110:
            return (PublicKey)new BC11XDHPublicKey(x25519Prefix, arrayOfByte);
          case 113:
            return (PublicKey)new BC15EdDSAPublicKey(Ed448Prefix, arrayOfByte);
          case 112:
            return (PublicKey)new BC15EdDSAPublicKey(Ed25519Prefix, arrayOfByte);
        } 
        return super.engineGeneratePublic(paramKeySpec);
      } 
    } else {
      if (paramKeySpec instanceof RawEncodedKeySpec) {
        byte[] arrayOfByte = ((RawEncodedKeySpec)paramKeySpec).getEncoded();
        switch (this.specificBase) {
          case 111:
            return (PublicKey)new BC11XDHPublicKey(new X448PublicKeyParameters(arrayOfByte));
          case 110:
            return (PublicKey)new BC11XDHPublicKey(new X25519PublicKeyParameters(arrayOfByte));
          case 113:
            return (PublicKey)new BC15EdDSAPublicKey(new Ed448PublicKeyParameters(arrayOfByte));
          case 112:
            return (PublicKey)new BC15EdDSAPublicKey(new Ed25519PublicKeyParameters(arrayOfByte));
        } 
        throw new InvalidKeySpecException("factory not a specific type, cannot recognise raw encoding");
      } 
      if (paramKeySpec instanceof OpenSSHPublicKeySpec) {
        AsymmetricKeyParameter asymmetricKeyParameter = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)paramKeySpec).getEncoded());
        if (asymmetricKeyParameter instanceof Ed25519PublicKeyParameters)
          return (PublicKey)new BC15EdDSAPublicKey(new byte[0], ((Ed25519PublicKeyParameters)asymmetricKeyParameter).getEncoded()); 
        throw new IllegalStateException("openssh public key not Ed25519 public key");
      } 
    } 
    return super.engineGeneratePublic(paramKeySpec);
  }
  
  public PrivateKey generatePrivate(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramPrivateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm();
    if (this.isXdh) {
      if ((this.specificBase == 0 || this.specificBase == 111) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_X448))
        return (PrivateKey)new BC11XDHPrivateKey(paramPrivateKeyInfo); 
      if ((this.specificBase == 0 || this.specificBase == 110) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_X25519))
        return (PrivateKey)new BC11XDHPrivateKey(paramPrivateKeyInfo); 
    } else if (aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed448) || aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed25519)) {
      if ((this.specificBase == 0 || this.specificBase == 113) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed448))
        return (PrivateKey)new BC15EdDSAPrivateKey(paramPrivateKeyInfo); 
      if ((this.specificBase == 0 || this.specificBase == 112) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed25519))
        return (PrivateKey)new BC15EdDSAPrivateKey(paramPrivateKeyInfo); 
    } 
    throw new IOException("algorithm identifier " + aSN1ObjectIdentifier + " in key not recognized");
  }
  
  public PublicKey generatePublic(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    ASN1ObjectIdentifier aSN1ObjectIdentifier = paramSubjectPublicKeyInfo.getAlgorithm().getAlgorithm();
    if (this.isXdh) {
      if ((this.specificBase == 0 || this.specificBase == 111) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_X448))
        return (PublicKey)new BC11XDHPublicKey(paramSubjectPublicKeyInfo); 
      if ((this.specificBase == 0 || this.specificBase == 110) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_X25519))
        return (PublicKey)new BC11XDHPublicKey(paramSubjectPublicKeyInfo); 
    } else if (aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed448) || aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed25519)) {
      if ((this.specificBase == 0 || this.specificBase == 113) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed448))
        return (PublicKey)new BC15EdDSAPublicKey(paramSubjectPublicKeyInfo); 
      if ((this.specificBase == 0 || this.specificBase == 112) && aSN1ObjectIdentifier.equals(EdECObjectIdentifiers.id_Ed25519))
        return (PublicKey)new BC15EdDSAPublicKey(paramSubjectPublicKeyInfo); 
    } 
    throw new IOException("algorithm identifier " + aSN1ObjectIdentifier + " in key not recognized");
  }
}
