package META-INF.versions.9.org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;

public class DHDomainParameterSpec extends DHParameterSpec {
  private final BigInteger q;
  
  private final BigInteger j;
  
  private final int m;
  
  private DHValidationParameters validationParameters;
  
  public DHDomainParameterSpec(DHParameters paramDHParameters) {
    this(paramDHParameters.getP(), paramDHParameters.getQ(), paramDHParameters.getG(), paramDHParameters.getJ(), paramDHParameters.getM(), paramDHParameters.getL());
    this.validationParameters = paramDHParameters.getValidationParameters();
  }
  
  public DHDomainParameterSpec(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3) {
    this(paramBigInteger1, paramBigInteger2, paramBigInteger3, (BigInteger)null, 0);
  }
  
  public DHDomainParameterSpec(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3, int paramInt) {
    this(paramBigInteger1, paramBigInteger2, paramBigInteger3, (BigInteger)null, paramInt);
  }
  
  public DHDomainParameterSpec(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3, BigInteger paramBigInteger4, int paramInt) {
    this(paramBigInteger1, paramBigInteger2, paramBigInteger3, paramBigInteger4, 0, paramInt);
  }
  
  public DHDomainParameterSpec(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3, BigInteger paramBigInteger4, int paramInt1, int paramInt2) {
    super(paramBigInteger1, paramBigInteger3, paramInt2);
    this.q = paramBigInteger2;
    this.j = paramBigInteger4;
    this.m = paramInt1;
  }
  
  public BigInteger getQ() {
    return this.q;
  }
  
  public BigInteger getJ() {
    return this.j;
  }
  
  public int getM() {
    return this.m;
  }
  
  public DHParameters getDomainParameters() {
    return new DHParameters(getP(), getG(), this.q, this.m, getL(), this.j, this.validationParameters);
  }
}
