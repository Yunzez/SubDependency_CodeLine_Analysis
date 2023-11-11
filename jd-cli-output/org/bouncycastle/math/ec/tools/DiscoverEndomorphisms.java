package org.bouncycastle.math.ec.tools;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.TreeSet;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public class DiscoverEndomorphisms {
  private static final int radix = 16;
  
  public static void main(String[] paramArrayOfString) {
    if (paramArrayOfString.length > 0) {
      for (byte b = 0; b < paramArrayOfString.length; b++)
        discoverEndomorphisms(paramArrayOfString[b]); 
    } else {
      TreeSet treeSet = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
      treeSet.addAll(enumToList(CustomNamedCurves.getNames()));
      Iterator<String> iterator = treeSet.iterator();
      while (iterator.hasNext())
        discoverEndomorphisms(iterator.next()); 
    } 
  }
  
  public static void discoverEndomorphisms(X9ECParameters paramX9ECParameters) {
    if (paramX9ECParameters == null)
      throw new NullPointerException("x9"); 
    discoverEndomorphisms(paramX9ECParameters, "<UNKNOWN>");
  }
  
  private static void discoverEndomorphisms(String paramString) {
    X9ECParameters x9ECParameters = CustomNamedCurves.getByName(paramString);
    if (x9ECParameters == null) {
      x9ECParameters = ECNamedCurveTable.getByName(paramString);
      if (x9ECParameters == null) {
        System.err.println("Unknown curve: " + paramString);
        return;
      } 
    } 
    discoverEndomorphisms(x9ECParameters, paramString);
  }
  
  private static void discoverEndomorphisms(X9ECParameters paramX9ECParameters, String paramString) {
    ECCurve eCCurve = paramX9ECParameters.getCurve();
    if (ECAlgorithms.isFpCurve(eCCurve)) {
      BigInteger bigInteger = eCCurve.getField().getCharacteristic();
      if (eCCurve.getB().isZero() && bigInteger.mod(ECConstants.FOUR).equals(ECConstants.ONE)) {
        System.out.println("Curve '" + paramString + "' has a 'GLV Type A' endomorphism with these parameters:");
        printGLVTypeAParameters(paramX9ECParameters);
      } 
      if (eCCurve.getA().isZero() && bigInteger.mod(ECConstants.THREE).equals(ECConstants.ONE)) {
        System.out.println("Curve '" + paramString + "' has a 'GLV Type B' endomorphism with these parameters:");
        printGLVTypeBParameters(paramX9ECParameters);
      } 
    } 
  }
  
  private static void printGLVTypeAParameters(X9ECParameters paramX9ECParameters) {
    BigInteger[] arrayOfBigInteger = solveQuadraticEquation(paramX9ECParameters.getN(), ECConstants.ONE, ECConstants.ZERO, ECConstants.ONE);
    ECFieldElement[] arrayOfECFieldElement = findNonTrivialOrder4FieldElements(paramX9ECParameters.getCurve());
    printGLVTypeAParameters(paramX9ECParameters, arrayOfBigInteger[0], arrayOfECFieldElement);
    System.out.println("OR");
    printGLVTypeAParameters(paramX9ECParameters, arrayOfBigInteger[1], arrayOfECFieldElement);
  }
  
  private static void printGLVTypeAParameters(X9ECParameters paramX9ECParameters, BigInteger paramBigInteger, ECFieldElement[] paramArrayOfECFieldElement) {
    ECPoint eCPoint1 = paramX9ECParameters.getG().normalize();
    ECPoint eCPoint2 = eCPoint1.multiply(paramBigInteger).normalize();
    if (!eCPoint1.getXCoord().negate().equals(eCPoint2.getXCoord()))
      throw new IllegalStateException("Derivation of GLV Type A parameters failed unexpectedly"); 
    ECFieldElement eCFieldElement = paramArrayOfECFieldElement[0];
    if (!eCPoint1.getYCoord().multiply(eCFieldElement).equals(eCPoint2.getYCoord())) {
      eCFieldElement = paramArrayOfECFieldElement[1];
      if (!eCPoint1.getYCoord().multiply(eCFieldElement).equals(eCPoint2.getYCoord()))
        throw new IllegalStateException("Derivation of GLV Type A parameters failed unexpectedly"); 
    } 
    printProperty("Point map", "lambda * (x, y) = (-x, i * y)");
    printProperty("i", eCFieldElement.toBigInteger().toString(16));
    printProperty("lambda", paramBigInteger.toString(16));
    printScalarDecompositionParameters(paramX9ECParameters.getN(), paramBigInteger);
  }
  
  private static void printGLVTypeBParameters(X9ECParameters paramX9ECParameters) {
    BigInteger[] arrayOfBigInteger = solveQuadraticEquation(paramX9ECParameters.getN(), ECConstants.ONE, ECConstants.ONE, ECConstants.ONE);
    ECFieldElement[] arrayOfECFieldElement = findNonTrivialOrder3FieldElements(paramX9ECParameters.getCurve());
    printGLVTypeBParameters(paramX9ECParameters, arrayOfBigInteger[0], arrayOfECFieldElement);
    System.out.println("OR");
    printGLVTypeBParameters(paramX9ECParameters, arrayOfBigInteger[1], arrayOfECFieldElement);
  }
  
  private static void printGLVTypeBParameters(X9ECParameters paramX9ECParameters, BigInteger paramBigInteger, ECFieldElement[] paramArrayOfECFieldElement) {
    ECPoint eCPoint1 = paramX9ECParameters.getG().normalize();
    ECPoint eCPoint2 = eCPoint1.multiply(paramBigInteger).normalize();
    if (!eCPoint1.getYCoord().equals(eCPoint2.getYCoord()))
      throw new IllegalStateException("Derivation of GLV Type B parameters failed unexpectedly"); 
    ECFieldElement eCFieldElement = paramArrayOfECFieldElement[0];
    if (!eCPoint1.getXCoord().multiply(eCFieldElement).equals(eCPoint2.getXCoord())) {
      eCFieldElement = paramArrayOfECFieldElement[1];
      if (!eCPoint1.getXCoord().multiply(eCFieldElement).equals(eCPoint2.getXCoord()))
        throw new IllegalStateException("Derivation of GLV Type B parameters failed unexpectedly"); 
    } 
    printProperty("Point map", "lambda * (x, y) = (beta * x, y)");
    printProperty("beta", eCFieldElement.toBigInteger().toString(16));
    printProperty("lambda", paramBigInteger.toString(16));
    printScalarDecompositionParameters(paramX9ECParameters.getN(), paramBigInteger);
  }
  
  private static void printProperty(String paramString, Object paramObject) {
    StringBuffer stringBuffer = new StringBuffer("  ");
    stringBuffer.append(paramString);
    while (stringBuffer.length() < 20)
      stringBuffer.append(' '); 
    stringBuffer.append(": ");
    stringBuffer.append(paramObject.toString());
    System.out.println(stringBuffer.toString());
  }
  
  private static void printScalarDecompositionParameters(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    BigInteger[] arrayOfBigInteger1 = null;
    BigInteger[] arrayOfBigInteger2 = null;
    BigInteger[] arrayOfBigInteger3 = extEuclidGLV(paramBigInteger1, paramBigInteger2);
    arrayOfBigInteger1 = new BigInteger[] { arrayOfBigInteger3[2], arrayOfBigInteger3[3].negate() };
    arrayOfBigInteger2 = chooseShortest(new BigInteger[] { arrayOfBigInteger3[0], arrayOfBigInteger3[1].negate() }, new BigInteger[] { arrayOfBigInteger3[4], arrayOfBigInteger3[5].negate() });
    if (!isVectorBoundedBySqrt(arrayOfBigInteger2, paramBigInteger1) && areRelativelyPrime(arrayOfBigInteger1[0], arrayOfBigInteger1[1])) {
      BigInteger bigInteger4 = arrayOfBigInteger1[0];
      BigInteger bigInteger5 = arrayOfBigInteger1[1];
      BigInteger bigInteger6 = bigInteger4.add(bigInteger5.multiply(paramBigInteger2)).divide(paramBigInteger1);
      BigInteger[] arrayOfBigInteger = extEuclidBezout(new BigInteger[] { bigInteger6.abs(), bigInteger5.abs() });
      if (arrayOfBigInteger != null) {
        BigInteger bigInteger7 = arrayOfBigInteger[0];
        BigInteger bigInteger8 = arrayOfBigInteger[1];
        if (bigInteger6.signum() < 0)
          bigInteger7 = bigInteger7.negate(); 
        if (bigInteger5.signum() > 0)
          bigInteger8 = bigInteger8.negate(); 
        BigInteger bigInteger9 = bigInteger6.multiply(bigInteger7).subtract(bigInteger5.multiply(bigInteger8));
        if (!bigInteger9.equals(ECConstants.ONE))
          throw new IllegalStateException(); 
        BigInteger bigInteger10 = bigInteger8.multiply(paramBigInteger1).subtract(bigInteger7.multiply(paramBigInteger2));
        BigInteger bigInteger11 = bigInteger7.negate();
        BigInteger bigInteger12 = bigInteger10.negate();
        BigInteger bigInteger13 = isqrt(paramBigInteger1.subtract(ECConstants.ONE)).add(ECConstants.ONE);
        BigInteger[] arrayOfBigInteger4 = calculateRange(bigInteger11, bigInteger13, bigInteger5);
        BigInteger[] arrayOfBigInteger5 = calculateRange(bigInteger12, bigInteger13, bigInteger4);
        BigInteger[] arrayOfBigInteger6 = intersect(arrayOfBigInteger4, arrayOfBigInteger5);
        if (arrayOfBigInteger6 != null)
          for (BigInteger bigInteger = arrayOfBigInteger6[0]; bigInteger.compareTo(arrayOfBigInteger6[1]) <= 0; bigInteger = bigInteger.add(ECConstants.ONE)) {
            BigInteger[] arrayOfBigInteger7 = { bigInteger10.add(bigInteger.multiply(bigInteger4)), bigInteger7.add(bigInteger.multiply(bigInteger5)) };
            if (isShorter(arrayOfBigInteger7, arrayOfBigInteger2))
              arrayOfBigInteger2 = arrayOfBigInteger7; 
          }  
      } 
    } 
    BigInteger bigInteger1 = arrayOfBigInteger1[0].multiply(arrayOfBigInteger2[1]).subtract(arrayOfBigInteger1[1].multiply(arrayOfBigInteger2[0]));
    int i = paramBigInteger1.bitLength() + 16 - (paramBigInteger1.bitLength() & 0x7);
    BigInteger bigInteger2 = roundQuotient(arrayOfBigInteger2[1].shiftLeft(i), bigInteger1);
    BigInteger bigInteger3 = roundQuotient(arrayOfBigInteger1[1].shiftLeft(i), bigInteger1).negate();
    printProperty("v1", "{ " + arrayOfBigInteger1[0].toString(16) + ", " + arrayOfBigInteger1[1].toString(16) + " }");
    printProperty("v2", "{ " + arrayOfBigInteger2[0].toString(16) + ", " + arrayOfBigInteger2[1].toString(16) + " }");
    printProperty("d", bigInteger1.toString(16));
    printProperty("(OPT) g1", bigInteger2.toString(16));
    printProperty("(OPT) g2", bigInteger3.toString(16));
    printProperty("(OPT) bits", Integer.toString(i));
  }
  
  private static boolean areRelativelyPrime(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    return paramBigInteger1.gcd(paramBigInteger2).equals(ECConstants.ONE);
  }
  
  private static BigInteger[] calculateRange(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3) {
    BigInteger bigInteger1 = paramBigInteger1.subtract(paramBigInteger2).divide(paramBigInteger3);
    BigInteger bigInteger2 = paramBigInteger1.add(paramBigInteger2).divide(paramBigInteger3);
    return order(bigInteger1, bigInteger2);
  }
  
  private static ArrayList enumToList(Enumeration paramEnumeration) {
    ArrayList arrayList = new ArrayList();
    while (paramEnumeration.hasMoreElements())
      arrayList.add(paramEnumeration.nextElement()); 
    return arrayList;
  }
  
  private static BigInteger[] extEuclidBezout(BigInteger[] paramArrayOfBigInteger) {
    boolean bool = (paramArrayOfBigInteger[0].compareTo(paramArrayOfBigInteger[1]) < 0) ? true : false;
    if (bool)
      swap(paramArrayOfBigInteger); 
    BigInteger bigInteger1 = paramArrayOfBigInteger[0];
    BigInteger bigInteger2 = paramArrayOfBigInteger[1];
    BigInteger bigInteger3 = ECConstants.ONE;
    BigInteger bigInteger4 = ECConstants.ZERO;
    BigInteger bigInteger5 = ECConstants.ZERO;
    BigInteger bigInteger6;
    for (bigInteger6 = ECConstants.ONE; bigInteger2.compareTo(ECConstants.ONE) > 0; bigInteger6 = bigInteger10) {
      BigInteger[] arrayOfBigInteger1 = bigInteger1.divideAndRemainder(bigInteger2);
      BigInteger bigInteger7 = arrayOfBigInteger1[0];
      BigInteger bigInteger8 = arrayOfBigInteger1[1];
      BigInteger bigInteger9 = bigInteger3.subtract(bigInteger7.multiply(bigInteger4));
      BigInteger bigInteger10 = bigInteger5.subtract(bigInteger7.multiply(bigInteger6));
      bigInteger1 = bigInteger2;
      bigInteger2 = bigInteger8;
      bigInteger3 = bigInteger4;
      bigInteger4 = bigInteger9;
      bigInteger5 = bigInteger6;
    } 
    if (bigInteger2.signum() <= 0)
      return null; 
    BigInteger[] arrayOfBigInteger = { bigInteger4, bigInteger6 };
    if (bool)
      swap(arrayOfBigInteger); 
    return arrayOfBigInteger;
  }
  
  private static BigInteger[] extEuclidGLV(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    BigInteger bigInteger1 = paramBigInteger1;
    BigInteger bigInteger2 = paramBigInteger2;
    BigInteger bigInteger3 = ECConstants.ZERO;
    for (BigInteger bigInteger4 = ECConstants.ONE;; bigInteger4 = bigInteger7) {
      BigInteger[] arrayOfBigInteger = bigInteger1.divideAndRemainder(bigInteger2);
      BigInteger bigInteger5 = arrayOfBigInteger[0];
      BigInteger bigInteger6 = arrayOfBigInteger[1];
      BigInteger bigInteger7 = bigInteger3.subtract(bigInteger5.multiply(bigInteger4));
      if (isLessThanSqrt(bigInteger2, paramBigInteger1))
        return new BigInteger[] { bigInteger1, bigInteger3, bigInteger2, bigInteger4, bigInteger6, bigInteger7 }; 
      bigInteger1 = bigInteger2;
      bigInteger2 = bigInteger6;
      bigInteger3 = bigInteger4;
    } 
  }
  
  private static BigInteger[] chooseShortest(BigInteger[] paramArrayOfBigInteger1, BigInteger[] paramArrayOfBigInteger2) {
    return isShorter(paramArrayOfBigInteger1, paramArrayOfBigInteger2) ? paramArrayOfBigInteger1 : paramArrayOfBigInteger2;
  }
  
  private static BigInteger[] intersect(BigInteger[] paramArrayOfBigInteger1, BigInteger[] paramArrayOfBigInteger2) {
    BigInteger bigInteger1 = paramArrayOfBigInteger1[0].max(paramArrayOfBigInteger2[0]);
    BigInteger bigInteger2 = paramArrayOfBigInteger1[1].min(paramArrayOfBigInteger2[1]);
    return (bigInteger1.compareTo(bigInteger2) > 0) ? null : new BigInteger[] { bigInteger1, bigInteger2 };
  }
  
  private static boolean isLessThanSqrt(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    paramBigInteger1 = paramBigInteger1.abs();
    paramBigInteger2 = paramBigInteger2.abs();
    int i = paramBigInteger2.bitLength();
    int j = paramBigInteger1.bitLength() * 2;
    int k = j - 1;
    return (k <= i && (j < i || paramBigInteger1.multiply(paramBigInteger1).compareTo(paramBigInteger2) < 0));
  }
  
  private static boolean isShorter(BigInteger[] paramArrayOfBigInteger1, BigInteger[] paramArrayOfBigInteger2) {
    BigInteger bigInteger1 = paramArrayOfBigInteger1[0].abs();
    BigInteger bigInteger2 = paramArrayOfBigInteger1[1].abs();
    BigInteger bigInteger3 = paramArrayOfBigInteger2[0].abs();
    BigInteger bigInteger4 = paramArrayOfBigInteger2[1].abs();
    boolean bool1 = (bigInteger1.compareTo(bigInteger3) < 0) ? true : false;
    boolean bool2 = (bigInteger2.compareTo(bigInteger4) < 0) ? true : false;
    if (bool1 == bool2)
      return bool1; 
    BigInteger bigInteger5 = bigInteger1.multiply(bigInteger1).add(bigInteger2.multiply(bigInteger2));
    BigInteger bigInteger6 = bigInteger3.multiply(bigInteger3).add(bigInteger4.multiply(bigInteger4));
    return (bigInteger5.compareTo(bigInteger6) < 0);
  }
  
  private static boolean isVectorBoundedBySqrt(BigInteger[] paramArrayOfBigInteger, BigInteger paramBigInteger) {
    BigInteger bigInteger = paramArrayOfBigInteger[0].abs().max(paramArrayOfBigInteger[1].abs());
    return isLessThanSqrt(bigInteger, paramBigInteger);
  }
  
  private static BigInteger[] order(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    return (paramBigInteger1.compareTo(paramBigInteger2) <= 0) ? new BigInteger[] { paramBigInteger1, paramBigInteger2 } : new BigInteger[] { paramBigInteger2, paramBigInteger1 };
  }
  
  private static BigInteger roundQuotient(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    boolean bool = (paramBigInteger1.signum() != paramBigInteger2.signum()) ? true : false;
    paramBigInteger1 = paramBigInteger1.abs();
    paramBigInteger2 = paramBigInteger2.abs();
    BigInteger bigInteger = paramBigInteger1.add(paramBigInteger2.shiftRight(1)).divide(paramBigInteger2);
    return bool ? bigInteger.negate() : bigInteger;
  }
  
  private static BigInteger[] solveQuadraticEquation(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3, BigInteger paramBigInteger4) {
    BigInteger bigInteger1 = paramBigInteger3.multiply(paramBigInteger3).subtract(paramBigInteger2.multiply(paramBigInteger4).shiftLeft(2)).mod(paramBigInteger1);
    BigInteger bigInteger2 = modSqrt(bigInteger1, paramBigInteger1);
    if (bigInteger2 == null)
      throw new IllegalStateException("Solving quadratic equation failed unexpectedly"); 
    BigInteger bigInteger3 = paramBigInteger2.shiftLeft(1).modInverse(paramBigInteger1);
    BigInteger bigInteger4 = bigInteger2.subtract(paramBigInteger3).multiply(bigInteger3).mod(paramBigInteger1);
    BigInteger bigInteger5 = bigInteger2.negate().subtract(paramBigInteger3).multiply(bigInteger3).mod(paramBigInteger1);
    return new BigInteger[] { bigInteger4, bigInteger5 };
  }
  
  private static ECFieldElement[] findNonTrivialOrder3FieldElements(ECCurve paramECCurve) {
    BigInteger bigInteger1 = paramECCurve.getField().getCharacteristic();
    BigInteger bigInteger2 = bigInteger1.divide(ECConstants.THREE);
    SecureRandom secureRandom = new SecureRandom();
    while (true) {
      BigInteger bigInteger4 = BigIntegers.createRandomInRange(ECConstants.TWO, bigInteger1.subtract(ECConstants.TWO), secureRandom);
      BigInteger bigInteger3 = bigInteger4.modPow(bigInteger2, bigInteger1);
      if (!bigInteger3.equals(ECConstants.ONE)) {
        ECFieldElement eCFieldElement = paramECCurve.fromBigInteger(bigInteger3);
        return new ECFieldElement[] { eCFieldElement, eCFieldElement.square() };
      } 
    } 
  }
  
  private static ECFieldElement[] findNonTrivialOrder4FieldElements(ECCurve paramECCurve) {
    ECFieldElement eCFieldElement = paramECCurve.fromBigInteger(ECConstants.ONE).negate().sqrt();
    if (eCFieldElement == null)
      throw new IllegalStateException("Calculation of non-trivial order-4  field elements failed unexpectedly"); 
    return new ECFieldElement[] { eCFieldElement, eCFieldElement.negate() };
  }
  
  private static BigInteger isqrt(BigInteger paramBigInteger) {
    for (BigInteger bigInteger = paramBigInteger.shiftRight(paramBigInteger.bitLength() / 2);; bigInteger = bigInteger1) {
      BigInteger bigInteger1 = bigInteger.add(paramBigInteger.divide(bigInteger)).shiftRight(1);
      if (bigInteger1.equals(bigInteger))
        return bigInteger1; 
    } 
  }
  
  private static void swap(BigInteger[] paramArrayOfBigInteger) {
    BigInteger bigInteger = paramArrayOfBigInteger[0];
    paramArrayOfBigInteger[0] = paramArrayOfBigInteger[1];
    paramArrayOfBigInteger[1] = bigInteger;
  }
  
  private static BigInteger modSqrt(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    if (!paramBigInteger2.testBit(0))
      throw new IllegalStateException(); 
    BigInteger bigInteger1 = paramBigInteger2.subtract(ECConstants.ONE).shiftRight(1);
    BigInteger bigInteger2 = bigInteger1;
    if (!paramBigInteger1.modPow(bigInteger2, paramBigInteger2).equals(ECConstants.ONE))
      return null; 
    while (!bigInteger2.testBit(0)) {
      bigInteger2 = bigInteger2.shiftRight(1);
      if (!paramBigInteger1.modPow(bigInteger2, paramBigInteger2).equals(ECConstants.ONE))
        return modSqrtComplex(paramBigInteger1, bigInteger2, paramBigInteger2, bigInteger1); 
    } 
    bigInteger2 = bigInteger2.add(ECConstants.ONE).shiftRight(1);
    return paramBigInteger1.modPow(bigInteger2, paramBigInteger2);
  }
  
  private static BigInteger modSqrtComplex(BigInteger paramBigInteger1, BigInteger paramBigInteger2, BigInteger paramBigInteger3, BigInteger paramBigInteger4) {
    BigInteger bigInteger1 = firstNonResidue(paramBigInteger3, paramBigInteger4);
    BigInteger bigInteger2 = paramBigInteger4;
    BigInteger bigInteger3 = bigInteger2;
    while (!paramBigInteger2.testBit(0)) {
      paramBigInteger2 = paramBigInteger2.shiftRight(1);
      bigInteger2 = bigInteger2.shiftRight(1);
      if (!paramBigInteger1.modPow(paramBigInteger2, paramBigInteger3).equals(bigInteger1.modPow(bigInteger2, paramBigInteger3)))
        bigInteger2 = bigInteger2.add(bigInteger3); 
    } 
    paramBigInteger2 = paramBigInteger2.subtract(ECConstants.ONE).shiftRight(1);
    bigInteger2 = bigInteger2.shiftRight(1);
    BigInteger bigInteger4 = paramBigInteger1.modInverse(paramBigInteger3);
    BigInteger bigInteger5 = bigInteger4.modPow(paramBigInteger2, paramBigInteger3);
    BigInteger bigInteger6 = bigInteger1.modPow(bigInteger2, paramBigInteger3);
    return bigInteger5.multiply(bigInteger6).mod(paramBigInteger3);
  }
  
  private static BigInteger firstNonResidue(BigInteger paramBigInteger1, BigInteger paramBigInteger2) {
    for (byte b = 2; b < 'Ϩ'; b++) {
      BigInteger bigInteger = BigInteger.valueOf(b);
      if (!bigInteger.modPow(paramBigInteger2, paramBigInteger1).equals(ECConstants.ONE))
        return bigInteger; 
    } 
    throw new IllegalStateException();
  }
}
