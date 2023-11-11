package org.bouncycastle.math.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Random;
import org.bouncycastle.math.ec.endo.ECEndomorphism;
import org.bouncycastle.math.ec.endo.GLVEndomorphism;
import org.bouncycastle.math.field.FiniteField;
import org.bouncycastle.math.field.FiniteFields;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

public abstract class ECCurve {
  public static final int COORD_AFFINE = 0;
  
  public static final int COORD_HOMOGENEOUS = 1;
  
  public static final int COORD_JACOBIAN = 2;
  
  public static final int COORD_JACOBIAN_CHUDNOVSKY = 3;
  
  public static final int COORD_JACOBIAN_MODIFIED = 4;
  
  public static final int COORD_LAMBDA_AFFINE = 5;
  
  public static final int COORD_LAMBDA_PROJECTIVE = 6;
  
  public static final int COORD_SKEWED = 7;
  
  protected FiniteField field;
  
  protected ECFieldElement a;
  
  protected ECFieldElement b;
  
  protected BigInteger order;
  
  protected BigInteger cofactor;
  
  protected int coord = 0;
  
  protected ECEndomorphism endomorphism = null;
  
  protected ECMultiplier multiplier = null;
  
  public static int[] getAllCoordinateSystems() {
    return new int[] { 0, 1, 2, 3, 4, 5, 6, 7 };
  }
  
  protected ECCurve(FiniteField paramFiniteField) {
    this.field = paramFiniteField;
  }
  
  public abstract int getFieldSize();
  
  public abstract ECFieldElement fromBigInteger(BigInteger paramBigInteger);
  
  public abstract boolean isValidFieldElement(BigInteger paramBigInteger);
  
  public abstract ECFieldElement randomFieldElement(SecureRandom paramSecureRandom);
  
  public abstract ECFieldElement randomFieldElementMult(SecureRandom paramSecureRandom);
  
  public synchronized Config configure() {
    return new Config(this.coord, this.endomorphism, this.multiplier);
  }
  
  public ECPoint validatePoint(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    ECPoint eCPoint = createPoint(paramBigInteger1, paramBigInteger2);
    if (!eCPoint.isValid())
      throw new IllegalArgumentException("Invalid point coordinates"); 
    return eCPoint;
  }
  
  public ECPoint createPoint(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    return createRawPoint(fromBigInteger(paramBigInteger1), fromBigInteger(paramBigInteger2));
  }
  
  protected abstract ECCurve cloneCurve();
  
  protected abstract ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2);
  
  protected abstract ECPoint createRawPoint(ECFieldElement paramECFieldElement1, ECFieldElement paramECFieldElement2, ECFieldElement[] paramArrayOfECFieldElement);
  
  protected ECMultiplier createDefaultMultiplier() {
    return (ECMultiplier)((this.endomorphism instanceof GLVEndomorphism) ? new GLVMultiplier(this, (GLVEndomorphism)this.endomorphism) : new WNafL2RMultiplier());
  }
  
  public boolean supportsCoordinateSystem(int paramInt) {
    return (paramInt == 0);
  }
  
  public PreCompInfo getPreCompInfo(ECPoint paramECPoint, String paramString) {
    Hashtable hashtable;
    checkPoint(paramECPoint);
    synchronized (paramECPoint) {
      hashtable = paramECPoint.preCompTable;
    } 
    if (null == hashtable)
      return null; 
    synchronized (hashtable) {
      return (PreCompInfo)hashtable.get(paramString);
    } 
  }
  
  public PreCompInfo precompute(ECPoint paramECPoint, String paramString, PreCompCallback paramPreCompCallback) {
    Hashtable<Object, Object> hashtable;
    checkPoint(paramECPoint);
    synchronized (paramECPoint) {
      hashtable = paramECPoint.preCompTable;
      if (null == hashtable)
        paramECPoint.preCompTable = hashtable = new Hashtable<Object, Object>(4); 
    } 
    synchronized (hashtable) {
      PreCompInfo preCompInfo1 = (PreCompInfo)hashtable.get(paramString);
      PreCompInfo preCompInfo2 = paramPreCompCallback.precompute(preCompInfo1);
      if (preCompInfo2 != preCompInfo1)
        hashtable.put(paramString, preCompInfo2); 
      return preCompInfo2;
    } 
  }
  
  public ECPoint importPoint(ECPoint paramECPoint) {
    if (this == paramECPoint.getCurve())
      return paramECPoint; 
    if (paramECPoint.isInfinity())
      return getInfinity(); 
    paramECPoint = paramECPoint.normalize();
    return createPoint(paramECPoint.getXCoord().toBigInteger(), paramECPoint.getYCoord().toBigInteger());
  }
  
  public void normalizeAll(ECPoint[] paramArrayOfECPoint) {
    normalizeAll(paramArrayOfECPoint, 0, paramArrayOfECPoint.length, null);
  }
  
  public void normalizeAll(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2, ECFieldElement paramECFieldElement) {
    checkPoints(paramArrayOfECPoint, paramInt1, paramInt2);
    switch (getCoordinateSystem()) {
      case 0:
      case 5:
        if (paramECFieldElement != null)
          throw new IllegalArgumentException("'iso' not valid for affine coordinates"); 
        return;
    } 
    ECFieldElement[] arrayOfECFieldElement = new ECFieldElement[paramInt2];
    int[] arrayOfInt = new int[paramInt2];
    byte b1 = 0;
    byte b2;
    for (b2 = 0; b2 < paramInt2; b2++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b2];
      if (null != eCPoint && (paramECFieldElement != null || !eCPoint.isNormalized())) {
        arrayOfECFieldElement[b1] = eCPoint.getZCoord(0);
        arrayOfInt[b1++] = paramInt1 + b2;
      } 
    } 
    if (b1 == 0)
      return; 
    ECAlgorithms.montgomeryTrick(arrayOfECFieldElement, 0, b1, paramECFieldElement);
    for (b2 = 0; b2 < b1; b2++) {
      int i = arrayOfInt[b2];
      paramArrayOfECPoint[i] = paramArrayOfECPoint[i].normalize(arrayOfECFieldElement[b2]);
    } 
  }
  
  public abstract ECPoint getInfinity();
  
  public FiniteField getField() {
    return this.field;
  }
  
  public ECFieldElement getA() {
    return this.a;
  }
  
  public ECFieldElement getB() {
    return this.b;
  }
  
  public BigInteger getOrder() {
    return this.order;
  }
  
  public BigInteger getCofactor() {
    return this.cofactor;
  }
  
  public int getCoordinateSystem() {
    return this.coord;
  }
  
  protected abstract ECPoint decompressPoint(int paramInt, BigInteger paramBigInteger);
  
  public ECEndomorphism getEndomorphism() {
    return this.endomorphism;
  }
  
  public ECMultiplier getMultiplier() {
    if (this.multiplier == null)
      this.multiplier = createDefaultMultiplier(); 
    return this.multiplier;
  }
  
  public ECPoint decodePoint(byte[] paramArrayOfbyte) {
    int j;
    BigInteger bigInteger1;
    BigInteger bigInteger2;
    ECPoint eCPoint = null;
    int i = (getFieldSize() + 7) / 8;
    byte b = paramArrayOfbyte[0];
    switch (b) {
      case 0:
        if (paramArrayOfbyte.length != 1)
          throw new IllegalArgumentException("Incorrect length for infinity encoding"); 
        eCPoint = getInfinity();
        break;
      case 2:
      case 3:
        if (paramArrayOfbyte.length != i + 1)
          throw new IllegalArgumentException("Incorrect length for compressed encoding"); 
        j = b & 0x1;
        bigInteger2 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1, i);
        eCPoint = decompressPoint(j, bigInteger2);
        if (!eCPoint.implIsValid(true, true))
          throw new IllegalArgumentException("Invalid point"); 
        break;
      case 4:
        if (paramArrayOfbyte.length != 2 * i + 1)
          throw new IllegalArgumentException("Incorrect length for uncompressed encoding"); 
        bigInteger1 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1, i);
        bigInteger2 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1 + i, i);
        eCPoint = validatePoint(bigInteger1, bigInteger2);
        break;
      case 6:
      case 7:
        if (paramArrayOfbyte.length != 2 * i + 1)
          throw new IllegalArgumentException("Incorrect length for hybrid encoding"); 
        bigInteger1 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1, i);
        bigInteger2 = BigIntegers.fromUnsignedByteArray(paramArrayOfbyte, 1 + i, i);
        if (bigInteger2.testBit(0) != ((b == 7)))
          throw new IllegalArgumentException("Inconsistent Y coordinate in hybrid encoding"); 
        eCPoint = validatePoint(bigInteger1, bigInteger2);
        break;
      default:
        throw new IllegalArgumentException("Invalid point encoding 0x" + Integer.toString(b, 16));
    } 
    if (b != 0 && eCPoint.isInfinity())
      throw new IllegalArgumentException("Invalid infinity encoding"); 
    return eCPoint;
  }
  
  public ECLookupTable createCacheSafeLookupTable(ECPoint[] paramArrayOfECPoint, int paramInt1, final int len) {
    final int FE_BYTES = getFieldSize() + 7 >>> 3;
    final byte[] table = new byte[len * i * 2];
    int j = 0;
    for (byte b = 0; b < len; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      byte[] arrayOfByte1 = eCPoint.getRawXCoord().toBigInteger().toByteArray();
      byte[] arrayOfByte2 = eCPoint.getRawYCoord().toBigInteger().toByteArray();
      byte b1 = (arrayOfByte1.length > i) ? 1 : 0;
      int k = arrayOfByte1.length - b1;
      byte b2 = (arrayOfByte2.length > i) ? 1 : 0;
      int m = arrayOfByte2.length - b2;
      System.arraycopy(arrayOfByte1, b1, arrayOfByte, j + i - k, k);
      j += i;
      System.arraycopy(arrayOfByte2, b2, arrayOfByte, j + i - m, m);
      j += i;
    } 
    return new AbstractECLookupTable() {
        public int getSize() {
          return len;
        }
        
        public ECPoint lookup(int param1Int) {
          byte[] arrayOfByte1 = new byte[FE_BYTES];
          byte[] arrayOfByte2 = new byte[FE_BYTES];
          int i = 0;
          for (byte b = 0; b < len; b++) {
            int j = (b ^ param1Int) - 1 >> 31;
            for (byte b1 = 0; b1 < FE_BYTES; b1++) {
              arrayOfByte1[b1] = (byte)(arrayOfByte1[b1] ^ table[i + b1] & j);
              arrayOfByte2[b1] = (byte)(arrayOfByte2[b1] ^ table[i + FE_BYTES + b1] & j);
            } 
            i += FE_BYTES * 2;
          } 
          return createPoint(arrayOfByte1, arrayOfByte2);
        }
        
        public ECPoint lookupVar(int param1Int) {
          byte[] arrayOfByte1 = new byte[FE_BYTES];
          byte[] arrayOfByte2 = new byte[FE_BYTES];
          int i = param1Int * FE_BYTES * 2;
          for (byte b = 0; b < FE_BYTES; b++) {
            arrayOfByte1[b] = table[i + b];
            arrayOfByte2[b] = table[i + FE_BYTES + b];
          } 
          return createPoint(arrayOfByte1, arrayOfByte2);
        }
        
        private ECPoint createPoint(byte[] param1ArrayOfbyte1, byte[] param1ArrayOfbyte2) {
          return ECCurve.this.createRawPoint(ECCurve.this.fromBigInteger(new BigInteger(1, param1ArrayOfbyte1)), ECCurve.this.fromBigInteger(new BigInteger(1, param1ArrayOfbyte2)));
        }
      };
  }
  
  protected void checkPoint(ECPoint paramECPoint) {
    if (null == paramECPoint || this != paramECPoint.getCurve())
      throw new IllegalArgumentException("'point' must be non-null and on this curve"); 
  }
  
  protected void checkPoints(ECPoint[] paramArrayOfECPoint) {
    checkPoints(paramArrayOfECPoint, 0, paramArrayOfECPoint.length);
  }
  
  protected void checkPoints(ECPoint[] paramArrayOfECPoint, int paramInt1, int paramInt2) {
    if (paramArrayOfECPoint == null)
      throw new IllegalArgumentException("'points' cannot be null"); 
    if (paramInt1 < 0 || paramInt2 < 0 || paramInt1 > paramArrayOfECPoint.length - paramInt2)
      throw new IllegalArgumentException("invalid range specified for 'points'"); 
    for (byte b = 0; b < paramInt2; b++) {
      ECPoint eCPoint = paramArrayOfECPoint[paramInt1 + b];
      if (null != eCPoint && this != eCPoint.getCurve())
        throw new IllegalArgumentException("'points' entries must be null or on this curve"); 
    } 
  }
  
  public boolean equals(ECCurve paramECCurve) {
    return (this == paramECCurve || (null != paramECCurve && getField().equals(paramECCurve.getField()) && getA().toBigInteger().equals(paramECCurve.getA().toBigInteger()) && getB().toBigInteger().equals(paramECCurve.getB().toBigInteger())));
  }
  
  public boolean equals(Object paramObject) {
    return (this == paramObject || (paramObject instanceof ECCurve && equals((ECCurve)paramObject)));
  }
  
  public int hashCode() {
    return getField().hashCode() ^ Integers.rotateLeft(getA().toBigInteger().hashCode(), 8) ^ Integers.rotateLeft(getB().toBigInteger().hashCode(), 16);
  }
  
  public static abstract class AbstractF2m extends ECCurve {
    private BigInteger[] si = null;
    
    public static BigInteger inverse(int param1Int, int[] param1ArrayOfint, BigInteger param1BigInteger) {
      return (new LongArray(param1BigInteger)).modInverse(param1Int, param1ArrayOfint).toBigInteger();
    }
    
    private static FiniteField buildField(int param1Int1, int param1Int2, int param1Int3, int param1Int4) {
      if (param1Int2 == 0)
        throw new IllegalArgumentException("k1 must be > 0"); 
      if (param1Int3 == 0) {
        if (param1Int4 != 0)
          throw new IllegalArgumentException("k3 must be 0 if k2 == 0"); 
        return FiniteFields.getBinaryExtensionField(new int[] { 0, param1Int2, param1Int1 });
      } 
      if (param1Int3 <= param1Int2)
        throw new IllegalArgumentException("k2 must be > k1"); 
      if (param1Int4 <= param1Int3)
        throw new IllegalArgumentException("k3 must be > k2"); 
      return FiniteFields.getBinaryExtensionField(new int[] { 0, param1Int2, param1Int3, param1Int4, param1Int1 });
    }
    
    protected AbstractF2m(int param1Int1, int param1Int2, int param1Int3, int param1Int4) {
      super(buildField(param1Int1, param1Int2, param1Int3, param1Int4));
    }
    
    public ECPoint createPoint(BigInteger param1BigInteger1, BigInteger param1BigInteger2) {
      ECFieldElement eCFieldElement1 = fromBigInteger(param1BigInteger1);
      ECFieldElement eCFieldElement2 = fromBigInteger(param1BigInteger2);
      int i = getCoordinateSystem();
      switch (i) {
        case 5:
        case 6:
          if (eCFieldElement1.isZero()) {
            if (!eCFieldElement2.square().equals(getB()))
              throw new IllegalArgumentException(); 
            break;
          } 
          eCFieldElement2 = eCFieldElement2.divide(eCFieldElement1).add(eCFieldElement1);
          break;
      } 
      return createRawPoint(eCFieldElement1, eCFieldElement2);
    }
    
    public boolean isValidFieldElement(BigInteger param1BigInteger) {
      return (param1BigInteger != null && param1BigInteger.signum() >= 0 && param1BigInteger.bitLength() <= getFieldSize());
    }
    
    public ECFieldElement randomFieldElement(SecureRandom param1SecureRandom) {
      int i = getFieldSize();
      return fromBigInteger(BigIntegers.createRandomBigInteger(i, param1SecureRandom));
    }
    
    public ECFieldElement randomFieldElementMult(SecureRandom param1SecureRandom) {
      int i = getFieldSize();
      ECFieldElement eCFieldElement1 = fromBigInteger(implRandomFieldElementMult(param1SecureRandom, i));
      ECFieldElement eCFieldElement2 = fromBigInteger(implRandomFieldElementMult(param1SecureRandom, i));
      return eCFieldElement1.multiply(eCFieldElement2);
    }
    
    protected ECPoint decompressPoint(int param1Int, BigInteger param1BigInteger) {
      ECFieldElement eCFieldElement1 = fromBigInteger(param1BigInteger);
      ECFieldElement eCFieldElement2 = null;
      if (eCFieldElement1.isZero()) {
        eCFieldElement2 = getB().sqrt();
      } else {
        ECFieldElement eCFieldElement3 = eCFieldElement1.square().invert().multiply(getB()).add(getA()).add(eCFieldElement1);
        ECFieldElement eCFieldElement4 = solveQuadraticEquation(eCFieldElement3);
        if (eCFieldElement4 != null) {
          if (eCFieldElement4.testBitZero() != ((param1Int == 1)))
            eCFieldElement4 = eCFieldElement4.addOne(); 
          switch (getCoordinateSystem()) {
            case 5:
            case 6:
              eCFieldElement2 = eCFieldElement4.add(eCFieldElement1);
              break;
            default:
              eCFieldElement2 = eCFieldElement4.multiply(eCFieldElement1);
              break;
          } 
        } 
      } 
      if (eCFieldElement2 == null)
        throw new IllegalArgumentException("Invalid point compression"); 
      return createRawPoint(eCFieldElement1, eCFieldElement2);
    }
    
    protected ECFieldElement solveQuadraticEquation(ECFieldElement param1ECFieldElement) {
      ECFieldElement.AbstractF2m abstractF2m = (ECFieldElement.AbstractF2m)param1ECFieldElement;
      boolean bool = abstractF2m.hasFastTrace();
      if (bool && 0 != abstractF2m.trace())
        return null; 
      int i = getFieldSize();
      if (0 != (i & 0x1)) {
        ECFieldElement eCFieldElement1 = abstractF2m.halfTrace();
        return (bool || eCFieldElement1.square().add(eCFieldElement1).add(param1ECFieldElement).isZero()) ? eCFieldElement1 : null;
      } 
      if (param1ECFieldElement.isZero())
        return param1ECFieldElement; 
      ECFieldElement eCFieldElement = fromBigInteger(ECConstants.ZERO);
      Random random = new Random();
      while (true) {
        ECFieldElement eCFieldElement3 = fromBigInteger(new BigInteger(i, random));
        ECFieldElement eCFieldElement2 = eCFieldElement;
        ECFieldElement eCFieldElement4 = param1ECFieldElement;
        for (byte b = 1; b < i; b++) {
          ECFieldElement eCFieldElement5 = eCFieldElement4.square();
          eCFieldElement2 = eCFieldElement2.square().add(eCFieldElement5.multiply(eCFieldElement3));
          eCFieldElement4 = eCFieldElement5.add(param1ECFieldElement);
        } 
        if (!eCFieldElement4.isZero())
          return null; 
        ECFieldElement eCFieldElement1 = eCFieldElement2.square().add(eCFieldElement2);
        if (!eCFieldElement1.isZero())
          return eCFieldElement2; 
      } 
    }
    
    synchronized BigInteger[] getSi() {
      if (this.si == null)
        this.si = Tnaf.getSi(this); 
      return this.si;
    }
    
    public boolean isKoblitz() {
      return (this.order != null && this.cofactor != null && this.b.isOne() && (this.a.isZero() || this.a.isOne()));
    }
    
    private static BigInteger implRandomFieldElementMult(SecureRandom param1SecureRandom, int param1Int) {
      while (true) {
        BigInteger bigInteger = BigIntegers.createRandomBigInteger(param1Int, param1SecureRandom);
        if (bigInteger.signum() > 0)
          return bigInteger; 
      } 
    }
  }
  
  public static abstract class AbstractFp extends ECCurve {
    protected AbstractFp(BigInteger param1BigInteger) {
      super(FiniteFields.getPrimeField(param1BigInteger));
    }
    
    public boolean isValidFieldElement(BigInteger param1BigInteger) {
      return (param1BigInteger != null && param1BigInteger.signum() >= 0 && param1BigInteger.compareTo(getField().getCharacteristic()) < 0);
    }
    
    public ECFieldElement randomFieldElement(SecureRandom param1SecureRandom) {
      BigInteger bigInteger = getField().getCharacteristic();
      ECFieldElement eCFieldElement1 = fromBigInteger(implRandomFieldElement(param1SecureRandom, bigInteger));
      ECFieldElement eCFieldElement2 = fromBigInteger(implRandomFieldElement(param1SecureRandom, bigInteger));
      return eCFieldElement1.multiply(eCFieldElement2);
    }
    
    public ECFieldElement randomFieldElementMult(SecureRandom param1SecureRandom) {
      BigInteger bigInteger = getField().getCharacteristic();
      ECFieldElement eCFieldElement1 = fromBigInteger(implRandomFieldElementMult(param1SecureRandom, bigInteger));
      ECFieldElement eCFieldElement2 = fromBigInteger(implRandomFieldElementMult(param1SecureRandom, bigInteger));
      return eCFieldElement1.multiply(eCFieldElement2);
    }
    
    protected ECPoint decompressPoint(int param1Int, BigInteger param1BigInteger) {
      ECFieldElement eCFieldElement1 = fromBigInteger(param1BigInteger);
      ECFieldElement eCFieldElement2 = eCFieldElement1.square().add(this.a).multiply(eCFieldElement1).add(this.b);
      ECFieldElement eCFieldElement3 = eCFieldElement2.sqrt();
      if (eCFieldElement3 == null)
        throw new IllegalArgumentException("Invalid point compression"); 
      if (eCFieldElement3.testBitZero() != ((param1Int == 1)))
        eCFieldElement3 = eCFieldElement3.negate(); 
      return createRawPoint(eCFieldElement1, eCFieldElement3);
    }
    
    private static BigInteger implRandomFieldElement(SecureRandom param1SecureRandom, BigInteger param1BigInteger) {
      while (true) {
        BigInteger bigInteger = BigIntegers.createRandomBigInteger(param1BigInteger.bitLength(), param1SecureRandom);
        if (bigInteger.compareTo(param1BigInteger) < 0)
          return bigInteger; 
      } 
    }
    
    private static BigInteger implRandomFieldElementMult(SecureRandom param1SecureRandom, BigInteger param1BigInteger) {
      while (true) {
        BigInteger bigInteger = BigIntegers.createRandomBigInteger(param1BigInteger.bitLength(), param1SecureRandom);
        if (bigInteger.signum() > 0 && bigInteger.compareTo(param1BigInteger) < 0)
          return bigInteger; 
      } 
    }
  }
  
  public class Config {
    protected int coord;
    
    protected ECEndomorphism endomorphism;
    
    protected ECMultiplier multiplier;
    
    Config(int param1Int, ECEndomorphism param1ECEndomorphism, ECMultiplier param1ECMultiplier) {
      this.coord = param1Int;
      this.endomorphism = param1ECEndomorphism;
      this.multiplier = param1ECMultiplier;
    }
    
    public Config setCoordinateSystem(int param1Int) {
      this.coord = param1Int;
      return this;
    }
    
    public Config setEndomorphism(ECEndomorphism param1ECEndomorphism) {
      this.endomorphism = param1ECEndomorphism;
      return this;
    }
    
    public Config setMultiplier(ECMultiplier param1ECMultiplier) {
      this.multiplier = param1ECMultiplier;
      return this;
    }
    
    public ECCurve create() {
      if (!ECCurve.this.supportsCoordinateSystem(this.coord))
        throw new IllegalStateException("unsupported coordinate system"); 
      ECCurve eCCurve = ECCurve.this.cloneCurve();
      if (eCCurve == ECCurve.this)
        throw new IllegalStateException("implementation returned current curve"); 
      synchronized (eCCurve) {
        eCCurve.coord = this.coord;
        eCCurve.endomorphism = this.endomorphism;
        eCCurve.multiplier = this.multiplier;
      } 
      return eCCurve;
    }
  }
  
  public static class F2m extends AbstractF2m {
    private static final int F2M_DEFAULT_COORDS = 6;
    
    private int m;
    
    private int k1;
    
    private int k2;
    
    private int k3;
    
    private ECPoint.F2m infinity;
    
    public F2m(int param1Int1, int param1Int2, BigInteger param1BigInteger1, BigInteger param1BigInteger2) {
      this(param1Int1, param1Int2, 0, 0, param1BigInteger1, param1BigInteger2, (BigInteger)null, (BigInteger)null);
    }
    
    public F2m(int param1Int1, int param1Int2, BigInteger param1BigInteger1, BigInteger param1BigInteger2, BigInteger param1BigInteger3, BigInteger param1BigInteger4) {
      this(param1Int1, param1Int2, 0, 0, param1BigInteger1, param1BigInteger2, param1BigInteger3, param1BigInteger4);
    }
    
    public F2m(int param1Int1, int param1Int2, int param1Int3, int param1Int4, BigInteger param1BigInteger1, BigInteger param1BigInteger2) {
      this(param1Int1, param1Int2, param1Int3, param1Int4, param1BigInteger1, param1BigInteger2, (BigInteger)null, (BigInteger)null);
    }
    
    public F2m(int param1Int1, int param1Int2, int param1Int3, int param1Int4, BigInteger param1BigInteger1, BigInteger param1BigInteger2, BigInteger param1BigInteger3, BigInteger param1BigInteger4) {
      super(param1Int1, param1Int2, param1Int3, param1Int4);
      this.m = param1Int1;
      this.k1 = param1Int2;
      this.k2 = param1Int3;
      this.k3 = param1Int4;
      this.order = param1BigInteger3;
      this.cofactor = param1BigInteger4;
      this.infinity = new ECPoint.F2m(this, null, null);
      this.a = fromBigInteger(param1BigInteger1);
      this.b = fromBigInteger(param1BigInteger2);
      this.coord = 6;
    }
    
    protected F2m(int param1Int1, int param1Int2, int param1Int3, int param1Int4, ECFieldElement param1ECFieldElement1, ECFieldElement param1ECFieldElement2, BigInteger param1BigInteger1, BigInteger param1BigInteger2) {
      super(param1Int1, param1Int2, param1Int3, param1Int4);
      this.m = param1Int1;
      this.k1 = param1Int2;
      this.k2 = param1Int3;
      this.k3 = param1Int4;
      this.order = param1BigInteger1;
      this.cofactor = param1BigInteger2;
      this.infinity = new ECPoint.F2m(this, null, null);
      this.a = param1ECFieldElement1;
      this.b = param1ECFieldElement2;
      this.coord = 6;
    }
    
    protected ECCurve cloneCurve() {
      return new F2m(this.m, this.k1, this.k2, this.k3, this.a, this.b, this.order, this.cofactor);
    }
    
    public boolean supportsCoordinateSystem(int param1Int) {
      switch (param1Int) {
        case 0:
        case 1:
        case 6:
          return true;
      } 
      return false;
    }
    
    protected ECMultiplier createDefaultMultiplier() {
      return isKoblitz() ? new WTauNafMultiplier() : super.createDefaultMultiplier();
    }
    
    public int getFieldSize() {
      return this.m;
    }
    
    public ECFieldElement fromBigInteger(BigInteger param1BigInteger) {
      return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, param1BigInteger);
    }
    
    protected ECPoint createRawPoint(ECFieldElement param1ECFieldElement1, ECFieldElement param1ECFieldElement2) {
      return new ECPoint.F2m(this, param1ECFieldElement1, param1ECFieldElement2);
    }
    
    protected ECPoint createRawPoint(ECFieldElement param1ECFieldElement1, ECFieldElement param1ECFieldElement2, ECFieldElement[] param1ArrayOfECFieldElement) {
      return new ECPoint.F2m(this, param1ECFieldElement1, param1ECFieldElement2, param1ArrayOfECFieldElement);
    }
    
    public ECPoint getInfinity() {
      return this.infinity;
    }
    
    public int getM() {
      return this.m;
    }
    
    public boolean isTrinomial() {
      return (this.k2 == 0 && this.k3 == 0);
    }
    
    public int getK1() {
      return this.k1;
    }
    
    public int getK2() {
      return this.k2;
    }
    
    public int getK3() {
      return this.k3;
    }
    
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] param1ArrayOfECPoint, int param1Int1, final int len) {
      final int FE_LONGS = this.m + 63 >>> 6;
      (new int[1])[0] = this.k1;
      (new int[3])[0] = this.k1;
      (new int[3])[1] = this.k2;
      (new int[3])[2] = this.k3;
      final int[] ks = isTrinomial() ? new int[1] : new int[3];
      final long[] table = new long[len * i * 2];
      int j = 0;
      for (byte b = 0; b < len; b++) {
        ECPoint eCPoint = param1ArrayOfECPoint[param1Int1 + b];
        ((ECFieldElement.F2m)eCPoint.getRawXCoord()).x.copyTo(arrayOfLong, j);
        j += i;
        ((ECFieldElement.F2m)eCPoint.getRawYCoord()).x.copyTo(arrayOfLong, j);
        j += i;
      } 
      return new AbstractECLookupTable() {
          public int getSize() {
            return len;
          }
          
          public ECPoint lookup(int param2Int) {
            long[] arrayOfLong1 = Nat.create64(FE_LONGS);
            long[] arrayOfLong2 = Nat.create64(FE_LONGS);
            int i = 0;
            for (byte b = 0; b < len; b++) {
              long l = ((b ^ param2Int) - 1 >> 31);
              for (byte b1 = 0; b1 < FE_LONGS; b1++) {
                arrayOfLong1[b1] = arrayOfLong1[b1] ^ table[i + b1] & l;
                arrayOfLong2[b1] = arrayOfLong2[b1] ^ table[i + FE_LONGS + b1] & l;
              } 
              i += FE_LONGS * 2;
            } 
            return createPoint(arrayOfLong1, arrayOfLong2);
          }
          
          public ECPoint lookupVar(int param2Int) {
            long[] arrayOfLong1 = Nat.create64(FE_LONGS);
            long[] arrayOfLong2 = Nat.create64(FE_LONGS);
            int i = param2Int * FE_LONGS * 2;
            for (byte b = 0; b < FE_LONGS; b++) {
              arrayOfLong1[b] = table[i + b];
              arrayOfLong2[b] = table[i + FE_LONGS + b];
            } 
            return createPoint(arrayOfLong1, arrayOfLong2);
          }
          
          private ECPoint createPoint(long[] param2ArrayOflong1, long[] param2ArrayOflong2) {
            ECFieldElement.F2m f2m1 = new ECFieldElement.F2m(ECCurve.F2m.this.m, ks, new LongArray(param2ArrayOflong1));
            ECFieldElement.F2m f2m2 = new ECFieldElement.F2m(ECCurve.F2m.this.m, ks, new LongArray(param2ArrayOflong2));
            return ECCurve.F2m.this.createRawPoint(f2m1, f2m2);
          }
        };
    }
  }
  
  public static class Fp extends AbstractFp {
    private static final int FP_DEFAULT_COORDS = 4;
    
    BigInteger q;
    
    BigInteger r;
    
    ECPoint.Fp infinity;
    
    public Fp(BigInteger param1BigInteger1, BigInteger param1BigInteger2, BigInteger param1BigInteger3) {
      this(param1BigInteger1, param1BigInteger2, param1BigInteger3, (BigInteger)null, (BigInteger)null);
    }
    
    public Fp(BigInteger param1BigInteger1, BigInteger param1BigInteger2, BigInteger param1BigInteger3, BigInteger param1BigInteger4, BigInteger param1BigInteger5) {
      super(param1BigInteger1);
      this.q = param1BigInteger1;
      this.r = ECFieldElement.Fp.calculateResidue(param1BigInteger1);
      this.infinity = new ECPoint.Fp(this, null, null);
      this.a = fromBigInteger(param1BigInteger2);
      this.b = fromBigInteger(param1BigInteger3);
      this.order = param1BigInteger4;
      this.cofactor = param1BigInteger5;
      this.coord = 4;
    }
    
    protected Fp(BigInteger param1BigInteger1, BigInteger param1BigInteger2, ECFieldElement param1ECFieldElement1, ECFieldElement param1ECFieldElement2, BigInteger param1BigInteger3, BigInteger param1BigInteger4) {
      super(param1BigInteger1);
      this.q = param1BigInteger1;
      this.r = param1BigInteger2;
      this.infinity = new ECPoint.Fp(this, null, null);
      this.a = param1ECFieldElement1;
      this.b = param1ECFieldElement2;
      this.order = param1BigInteger3;
      this.cofactor = param1BigInteger4;
      this.coord = 4;
    }
    
    protected ECCurve cloneCurve() {
      return new Fp(this.q, this.r, this.a, this.b, this.order, this.cofactor);
    }
    
    public boolean supportsCoordinateSystem(int param1Int) {
      switch (param1Int) {
        case 0:
        case 1:
        case 2:
        case 4:
          return true;
      } 
      return false;
    }
    
    public BigInteger getQ() {
      return this.q;
    }
    
    public int getFieldSize() {
      return this.q.bitLength();
    }
    
    public ECFieldElement fromBigInteger(BigInteger param1BigInteger) {
      return new ECFieldElement.Fp(this.q, this.r, param1BigInteger);
    }
    
    protected ECPoint createRawPoint(ECFieldElement param1ECFieldElement1, ECFieldElement param1ECFieldElement2) {
      return new ECPoint.Fp(this, param1ECFieldElement1, param1ECFieldElement2);
    }
    
    protected ECPoint createRawPoint(ECFieldElement param1ECFieldElement1, ECFieldElement param1ECFieldElement2, ECFieldElement[] param1ArrayOfECFieldElement) {
      return new ECPoint.Fp(this, param1ECFieldElement1, param1ECFieldElement2, param1ArrayOfECFieldElement);
    }
    
    public ECPoint importPoint(ECPoint param1ECPoint) {
      if (this != param1ECPoint.getCurve() && getCoordinateSystem() == 2 && !param1ECPoint.isInfinity())
        switch (param1ECPoint.getCurve().getCoordinateSystem()) {
          case 2:
          case 3:
          case 4:
            return new ECPoint.Fp(this, fromBigInteger(param1ECPoint.x.toBigInteger()), fromBigInteger(param1ECPoint.y.toBigInteger()), new ECFieldElement[] { fromBigInteger(param1ECPoint.zs[0].toBigInteger()) });
        }  
      return super.importPoint(param1ECPoint);
    }
    
    public ECPoint getInfinity() {
      return this.infinity;
    }
  }
}
