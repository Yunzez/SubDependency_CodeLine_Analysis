package org.bouncycastle.jcajce.io;

import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;

public class OutputStreamFactory {
  public static OutputStream createStream(Signature paramSignature) {
    return new SignatureUpdatingOutputStream(paramSignature);
  }
  
  public static OutputStream createStream(MessageDigest paramMessageDigest) {
    return new DigestUpdatingOutputStream(paramMessageDigest);
  }
  
  public static OutputStream createStream(Mac paramMac) {
    return new MacUpdatingOutputStream(paramMac);
  }
}
