package org.bouncycastle.jcajce.provider.asymmetric.edec;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.crypto.params.X448PublicKeyParameters;
import org.bouncycastle.util.Fingerprint;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

class Utils {
  static boolean isValidPrefix(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (paramArrayOfbyte2.length < paramArrayOfbyte1.length)
      return !isValidPrefix(paramArrayOfbyte1, paramArrayOfbyte1); 
    int i = 0;
    for (byte b = 0; b != paramArrayOfbyte1.length; b++)
      i |= paramArrayOfbyte1[b] ^ paramArrayOfbyte2[b]; 
    return (i == 0);
  }
  
  static String keyToString(String paramString1, String paramString2, AsymmetricKeyParameter paramAsymmetricKeyParameter) {
    byte[] arrayOfByte;
    StringBuffer stringBuffer = new StringBuffer();
    String str = Strings.lineSeparator();
    if (paramAsymmetricKeyParameter instanceof X448PublicKeyParameters) {
      arrayOfByte = ((X448PublicKeyParameters)paramAsymmetricKeyParameter).getEncoded();
    } else if (paramAsymmetricKeyParameter instanceof Ed448PublicKeyParameters) {
      arrayOfByte = ((Ed448PublicKeyParameters)paramAsymmetricKeyParameter).getEncoded();
    } else if (paramAsymmetricKeyParameter instanceof X25519PublicKeyParameters) {
      arrayOfByte = ((X25519PublicKeyParameters)paramAsymmetricKeyParameter).getEncoded();
    } else {
      arrayOfByte = ((Ed25519PublicKeyParameters)paramAsymmetricKeyParameter).getEncoded();
    } 
    stringBuffer.append(paramString2).append(" ").append(paramString1).append(" [").append(generateKeyFingerprint(arrayOfByte)).append("]").append(str).append("    public data: ").append(Hex.toHexString(arrayOfByte)).append(str);
    return stringBuffer.toString();
  }
  
  private static String generateKeyFingerprint(byte[] paramArrayOfbyte) {
    return (new Fingerprint(paramArrayOfbyte)).toString();
  }
}
