package META-INF.versions.15.org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.math.BigInteger;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.util.Arrays;

class BC15EdDSAPublicKey extends BCEdDSAPublicKey implements EdECPublicKey {
  BC15EdDSAPublicKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) {
    super(paramAsymmetricKeyParameter);
  }
  
  BC15EdDSAPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    super(paramSubjectPublicKeyInfo);
  }
  
  BC15EdDSAPublicKey(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws InvalidKeySpecException {
    super(paramArrayOfbyte1, paramArrayOfbyte2);
  }
  
  public EdECPoint getPoint() {
    byte[] arrayOfByte = getPointEncoding();
    Arrays.reverseInPlace(arrayOfByte);
    boolean bool = ((arrayOfByte[0] & 0x80) != 0) ? true : false;
    arrayOfByte[0] = (byte)(arrayOfByte[0] & Byte.MAX_VALUE);
    return new EdECPoint(bool, new BigInteger(1, arrayOfByte));
  }
  
  public NamedParameterSpec getParams() {
    if (this.eddsaPublicKey instanceof org.bouncycastle.crypto.params.Ed448PublicKeyParameters)
      return NamedParameterSpec.ED448; 
    return NamedParameterSpec.ED25519;
  }
}
