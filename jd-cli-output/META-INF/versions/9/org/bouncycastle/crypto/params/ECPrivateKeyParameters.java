package META-INF.versions.9.org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;

public class ECPrivateKeyParameters extends ECKeyParameters {
  private final BigInteger d;
  
  public ECPrivateKeyParameters(BigInteger paramBigInteger, ECDomainParameters paramECDomainParameters) {
    super(true, paramECDomainParameters);
    this.d = paramECDomainParameters.validatePrivateScalar(paramBigInteger);
  }
  
  public BigInteger getD() {
    return this.d;
  }
}
