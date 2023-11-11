package META-INF.versions.11.org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.io.IOException;
import java.security.interfaces.XECPrivateKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Optional;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;
import org.bouncycastle.jcajce.interfaces.XDHPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC11XDHPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCXDHPrivateKey;

class BC11XDHPrivateKey extends BCXDHPrivateKey implements XECPrivateKey {
  BC11XDHPrivateKey(AsymmetricKeyParameter paramAsymmetricKeyParameter) {
    super(paramAsymmetricKeyParameter);
  }
  
  BC11XDHPrivateKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    super(paramPrivateKeyInfo);
  }
  
  public AlgorithmParameterSpec getParams() {
    if (this.xdhPrivateKey instanceof X448PrivateKeyParameters)
      return NamedParameterSpec.X448; 
    return NamedParameterSpec.X25519;
  }
  
  public XDHPublicKey getPublicKey() {
    if (this.xdhPrivateKey instanceof X448PrivateKeyParameters)
      return (XDHPublicKey)new BC11XDHPublicKey(((X448PrivateKeyParameters)this.xdhPrivateKey).generatePublicKey()); 
    return (XDHPublicKey)new BC11XDHPublicKey(((X25519PrivateKeyParameters)this.xdhPrivateKey).generatePublicKey());
  }
  
  public Optional<byte[]> getScalar() {
    if (this.xdhPrivateKey instanceof X448PrivateKeyParameters)
      return (Optional)Optional.of(((X448PrivateKeyParameters)this.xdhPrivateKey).getEncoded()); 
    return (Optional)Optional.of(((X25519PrivateKeyParameters)this.xdhPrivateKey).getEncoded());
  }
}
