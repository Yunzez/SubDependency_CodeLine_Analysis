package META-INF.versions.9.org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

public class ECDomainParameters implements ECConstants {
  private final ECCurve curve;
  
  private final byte[] seed;
  
  private final ECPoint G;
  
  private final BigInteger n;
  
  private final BigInteger h;
  
  private BigInteger hInv = null;
  
  public ECDomainParameters(X9ECParameters paramX9ECParameters) {
    this(paramX9ECParameters.getCurve(), paramX9ECParameters.getG(), paramX9ECParameters.getN(), paramX9ECParameters.getH(), paramX9ECParameters.getSeed());
  }
  
  public ECDomainParameters(ECCurve paramECCurve, ECPoint paramECPoint, BigInteger paramBigInteger) {
    this(paramECCurve, paramECPoint, paramBigInteger, ONE, null);
  }
  
  public ECDomainParameters(ECCurve paramECCurve, ECPoint paramECPoint, BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    this(paramECCurve, paramECPoint, paramBigInteger1, paramBigInteger2, null);
  }
  
  public ECDomainParameters(ECCurve paramECCurve, ECPoint paramECPoint, BigInteger paramBigInteger1, BigInteger paramBigInteger2, byte[] paramArrayOfbyte) {
    if (paramECCurve == null)
      throw new NullPointerException("curve"); 
    if (paramBigInteger1 == null)
      throw new NullPointerException("n"); 
    this.curve = paramECCurve;
    this.G = validatePublicPoint(paramECCurve, paramECPoint);
    this.n = paramBigInteger1;
    this.h = paramBigInteger2;
    this.seed = Arrays.clone(paramArrayOfbyte);
  }
  
  public ECCurve getCurve() {
    return this.curve;
  }
  
  public ECPoint getG() {
    return this.G;
  }
  
  public BigInteger getN() {
    return this.n;
  }
  
  public BigInteger getH() {
    return this.h;
  }
  
  public synchronized BigInteger getHInv() {
    if (this.hInv == null)
      this.hInv = BigIntegers.modOddInverseVar(this.n, this.h); 
    return this.hInv;
  }
  
  public byte[] getSeed() {
    return Arrays.clone(this.seed);
  }
  
  public boolean equals(Object paramObject) {
    if (this == paramObject)
      return true; 
    if (!(paramObject instanceof org.bouncycastle.crypto.params.ECDomainParameters))
      return false; 
    org.bouncycastle.crypto.params.ECDomainParameters eCDomainParameters = (org.bouncycastle.crypto.params.ECDomainParameters)paramObject;
    return (this.curve.equals(eCDomainParameters.curve) && this.G
      .equals(eCDomainParameters.G) && this.n
      .equals(eCDomainParameters.n));
  }
  
  public int hashCode() {
    int i = 4;
    i *= 257;
    i ^= this.curve.hashCode();
    i *= 257;
    i ^= this.G.hashCode();
    i *= 257;
    i ^= this.n.hashCode();
    return i;
  }
  
  public BigInteger validatePrivateScalar(BigInteger paramBigInteger) {
    if (null == paramBigInteger)
      throw new NullPointerException("Scalar cannot be null"); 
    if (paramBigInteger.compareTo(ECConstants.ONE) < 0 || paramBigInteger.compareTo(getN()) >= 0)
      throw new IllegalArgumentException("Scalar is not in the interval [1, n - 1]"); 
    return paramBigInteger;
  }
  
  public ECPoint validatePublicPoint(ECPoint paramECPoint) {
    return validatePublicPoint(getCurve(), paramECPoint);
  }
  
  static ECPoint validatePublicPoint(ECCurve paramECCurve, ECPoint paramECPoint) {
    if (null == paramECPoint)
      throw new NullPointerException("Point cannot be null"); 
    paramECPoint = ECAlgorithms.importPoint(paramECCurve, paramECPoint).normalize();
    if (paramECPoint.isInfinity())
      throw new IllegalArgumentException("Point at infinity"); 
    if (!paramECPoint.isValid())
      throw new IllegalArgumentException("Point not on curve"); 
    return paramECPoint;
  }
}
