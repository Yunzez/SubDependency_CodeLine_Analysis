package META-INF.versions.11.org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPublicKey;

class BC11XDHPublicKey extends BCXDHPublicKey implements XECPublicKey {
  BC11XDHPublicKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) {
    super(paramAsymmetricKeyParameter);
  }
  
  BC11XDHPublicKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) {
    super(paramSubjectPublicKeyInfo);
  }
  
  BC11XDHPublicKey(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) throws InvalidKeySpecException {
    super(paramArrayOfbyte1, paramArrayOfbyte2);
  }
  
  public AlgorithmParameterSpec getParams() {
    if (this.xdhPublicKey instanceof org.bouncycastle.crypto.params.X448PublicKeyParameters)
      return NamedParameterSpec.X448; 
    return NamedParameterSpec.X25519;
  }
}
