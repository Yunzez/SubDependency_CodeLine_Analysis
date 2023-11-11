package META-INF.versions.9.org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;

public class PublicKeyFactory {
  private static Map converters = new HashMap<>();
  
  static {
    converters.put(PQCObjectIdentifiers.qTESLA_p_I, new QTeslaConverter(null));
    converters.put(PQCObjectIdentifiers.qTESLA_p_III, new QTeslaConverter(null));
    converters.put(PQCObjectIdentifiers.sphincs256, new SPHINCSConverter(null));
    converters.put(PQCObjectIdentifiers.newHope, new NHConverter(null));
    converters.put(PQCObjectIdentifiers.xmss, new XMSSConverter(null));
    converters.put(PQCObjectIdentifiers.xmss_mt, new XMSSMTConverter(null));
    converters.put(IsaraObjectIdentifiers.id_alg_xmss, new XMSSConverter(null));
    converters.put(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTConverter(null));
    converters.put(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSConverter(null));
    converters.put(PQCObjectIdentifiers.mcElieceCca2, new McElieceCCA2Converter(null));
  }
  
  public static AsymmetricKeyParameter createKey(byte[] paramArrayOfbyte) throws IOException {
    return createKey(SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(paramArrayOfbyte)));
  }
  
  public static AsymmetricKeyParameter createKey(InputStream paramInputStream) throws IOException {
    return createKey(SubjectPublicKeyInfo.getInstance((new ASN1InputStream(paramInputStream)).readObject()));
  }
  
  public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo) throws IOException {
    return createKey(paramSubjectPublicKeyInfo, null);
  }
  
  public static AsymmetricKeyParameter createKey(SubjectPublicKeyInfo paramSubjectPublicKeyInfo, Object paramObject) throws IOException {
    AlgorithmIdentifier algorithmIdentifier = paramSubjectPublicKeyInfo.getAlgorithm();
    SubjectPublicKeyInfoConverter subjectPublicKeyInfoConverter = (SubjectPublicKeyInfoConverter)converters.get(algorithmIdentifier.getAlgorithm());
    if (subjectPublicKeyInfoConverter != null)
      return subjectPublicKeyInfoConverter.getPublicKeyParameters(paramSubjectPublicKeyInfo, paramObject); 
    throw new IOException("algorithm identifier in public key not recognised: " + algorithmIdentifier.getAlgorithm());
  }
}
