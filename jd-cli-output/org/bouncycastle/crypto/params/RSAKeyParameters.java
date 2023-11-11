package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.util.Properties;

public class RSAKeyParameters extends AsymmetricKeyParameter {
  private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger("8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f", 16);
  
  private static final BigInteger ONE = BigInteger.valueOf(1L);
  
  private BigInteger modulus;
  
  private BigInteger exponent;
  
  public RSAKeyParameters(boolean paramBoolean, BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    super(paramBoolean);
    if (!paramBoolean && (paramBigInteger2.intValue() & 0x1) == 0)
      throw new IllegalArgumentException("RSA publicExponent is even"); 
    this.modulus = validate(paramBigInteger1);
    this.exponent = paramBigInteger2;
  }
  
  private BigInteger validate(BigInteger paramBigInteger) {
    if ((paramBigInteger.intValue() & 0x1) == 0)
      throw new IllegalArgumentException("RSA modulus is even"); 
    if (Properties.isOverrideSet("org.bouncycastle.rsa.allow_unsafe_mod"))
      return paramBigInteger; 
    if (!paramBigInteger.gcd(SMALL_PRIMES_PRODUCT).equals(ONE))
      throw new IllegalArgumentException("RSA modulus has a small prime factor"); 
    return paramBigInteger;
  }
  
  public BigInteger getModulus() {
    return this.modulus;
  }
  
  public BigInteger getExponent() {
    return this.exponent;
  }
}
