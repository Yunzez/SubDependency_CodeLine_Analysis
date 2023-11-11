package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.xmss;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

class DigestUtil {
  static Digest getDigest(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_sha256))
      return new SHA256Digest(); 
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_sha512))
      return new SHA512Digest(); 
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_shake128))
      return new SHAKEDigest(128); 
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_shake256))
      return new SHAKEDigest(256); 
    throw new IllegalArgumentException("unrecognized digest OID: " + paramASN1ObjectIdentifier);
  }
  
  static ASN1ObjectIdentifier getDigestOID(String paramString) {
    if (paramString.equals("SHA-256"))
      return NISTObjectIdentifiers.id_sha256; 
    if (paramString.equals("SHA-512"))
      return NISTObjectIdentifiers.id_sha512; 
    if (paramString.equals("SHAKE128"))
      return NISTObjectIdentifiers.id_shake128; 
    if (paramString.equals("SHAKE256"))
      return NISTObjectIdentifiers.id_shake256; 
    throw new IllegalArgumentException("unrecognized digest: " + paramString);
  }
  
  public static byte[] getDigestResult(Digest paramDigest) {
    byte[] arrayOfByte = new byte[getDigestSize(paramDigest)];
    if (paramDigest instanceof Xof) {
      ((Xof)paramDigest).doFinal(arrayOfByte, 0, arrayOfByte.length);
    } else {
      paramDigest.doFinal(arrayOfByte, 0);
    } 
    return arrayOfByte;
  }
  
  public static int getDigestSize(Digest paramDigest) {
    if (paramDigest instanceof Xof)
      return paramDigest.getDigestSize() * 2; 
    return paramDigest.getDigestSize();
  }
  
  public static String getXMSSDigestName(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_sha256))
      return "SHA256"; 
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_sha512))
      return "SHA512"; 
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_shake128))
      return "SHAKE128"; 
    if (paramASN1ObjectIdentifier.equals(NISTObjectIdentifiers.id_shake256))
      return "SHAKE256"; 
    throw new IllegalArgumentException("unrecognized digest OID: " + paramASN1ObjectIdentifier);
  }
}
