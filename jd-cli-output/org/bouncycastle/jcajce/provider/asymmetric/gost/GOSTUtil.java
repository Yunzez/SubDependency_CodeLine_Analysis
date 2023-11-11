package org.bouncycastle.jcajce.provider.asymmetric.gost;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.GOST3410Parameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;

class GOSTUtil {
  static String privateKeyToString(String paramString, BigInteger paramBigInteger, GOST3410Parameters paramGOST3410Parameters) {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    BigInteger bigInteger = paramGOST3410Parameters.getA().modPow(paramBigInteger, paramGOST3410Parameters.getP());
    stringBuffer.append(paramString);
    stringBuffer.append(" Private Key [").append(generateKeyFingerprint(bigInteger, paramGOST3410Parameters)).append("]").append(str);
    stringBuffer.append("                  Y: ").append(bigInteger.toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  static String publicKeyToString(String paramString, BigInteger paramBigInteger, GOST3410Parameters paramGOST3410Parameters) {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append(paramString);
    stringBuffer.append(" Public Key [").append(generateKeyFingerprint(paramBigInteger, paramGOST3410Parameters)).append("]").append(str);
    stringBuffer.append("                 Y: ").append(paramBigInteger.toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  private static String generateKeyFingerprint(BigInteger paramBigInteger, GOST3410Parameters paramGOST3410Parameters) {
    return (new Fingerprint(Arrays.concatenate(paramBigInteger.toByteArray(), paramGOST3410Parameters.getP().toByteArray(), paramGOST3410Parameters.getA().toByteArray()))).toString();
  }
}
