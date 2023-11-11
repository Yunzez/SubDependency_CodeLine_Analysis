package META-INF.versions.9.org.bouncycastle.util;

import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Arrays;

public class Fingerprint {
  private static char[] encodingTable = new char[] { 
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 
      'a', 'b', 'c', 'd', 'e', 'f' };
  
  private final byte[] fingerprint;
  
  public Fingerprint(byte[] paramArrayOfbyte) {
    this(paramArrayOfbyte, 160);
  }
  
  public Fingerprint(byte[] paramArrayOfbyte, int paramInt) {
    this.fingerprint = calculateFingerprint(paramArrayOfbyte, paramInt);
  }
  
  public Fingerprint(byte[] paramArrayOfbyte, boolean paramBoolean) {
    if (paramBoolean) {
      this.fingerprint = calculateFingerprintSHA512_160(paramArrayOfbyte);
    } else {
      this.fingerprint = calculateFingerprint(paramArrayOfbyte);
    } 
  }
  
  public byte[] getFingerprint() {
    return Arrays.clone(this.fingerprint);
  }
  
  public String toString() {
    StringBuffer stringBuffer = new StringBuffer();
    for (byte b = 0; b != this.fingerprint.length; b++) {
      if (b)
        stringBuffer.append(":"); 
      stringBuffer.append(encodingTable[this.fingerprint[b] >>> 4 & 0xF]);
      stringBuffer.append(encodingTable[this.fingerprint[b] & 0xF]);
    } 
    return stringBuffer.toString();
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof org.bouncycastle.util.Fingerprint)
      return Arrays.areEqual(((org.bouncycastle.util.Fingerprint)paramObject).fingerprint, this.fingerprint); 
    return false;
  }
  
  public int hashCode() {
    return Arrays.hashCode(this.fingerprint);
  }
  
  public static byte[] calculateFingerprint(byte[] paramArrayOfbyte) {
    return calculateFingerprint(paramArrayOfbyte, 160);
  }
  
  public static byte[] calculateFingerprint(byte[] paramArrayOfbyte, int paramInt) {
    if (paramInt % 8 != 0)
      throw new IllegalArgumentException("bitLength must be a multiple of 8"); 
    SHAKEDigest sHAKEDigest = new SHAKEDigest(256);
    sHAKEDigest.update(paramArrayOfbyte, 0, paramArrayOfbyte.length);
    byte[] arrayOfByte = new byte[paramInt / 8];
    sHAKEDigest.doFinal(arrayOfByte, 0, paramInt / 8);
    return arrayOfByte;
  }
  
  public static byte[] calculateFingerprintSHA512_160(byte[] paramArrayOfbyte) {
    SHA512tDigest sHA512tDigest = new SHA512tDigest(160);
    sHA512tDigest.update(paramArrayOfbyte, 0, paramArrayOfbyte.length);
    byte[] arrayOfByte = new byte[sHA512tDigest.getDigestSize()];
    sHA512tDigest.doFinal(arrayOfByte, 0);
    return arrayOfByte;
  }
}
