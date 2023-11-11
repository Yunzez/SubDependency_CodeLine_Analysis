package org.bouncycastle.jcajce.provider.asymmetric.dh;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;

class DHUtil {
  static String privateKeyToString(String paramString, BigInteger paramBigInteger, DHParameters paramDHParameters) {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    BigInteger bigInteger = paramDHParameters.getG().modPow(paramBigInteger, paramDHParameters.getP());
    stringBuffer.append(paramString);
    stringBuffer.append(" Private Key [").append(generateKeyFingerprint(bigInteger, paramDHParameters)).append("]").append(str);
    stringBuffer.append("              Y: ").append(bigInteger.toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  static String publicKeyToString(String paramString, BigInteger paramBigInteger, DHParameters paramDHParameters) {
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    stringBuffer.append(paramString);
    stringBuffer.append(" Public Key [").append(generateKeyFingerprint(paramBigInteger, paramDHParameters)).append("]").append(str);
    stringBuffer.append("             Y: ").append(paramBigInteger.toString(16)).append(str);
    return stringBuffer.toString();
  }
  
  private static String generateKeyFingerprint(BigInteger paramBigInteger, DHParameters paramDHParameters) {
    return (new Fingerprint(Arrays.concatenate(paramBigInteger.toByteArray(), paramDHParameters.getP().toByteArray(), paramDHParameters.getG().toByteArray()))).toString();
  }
}
