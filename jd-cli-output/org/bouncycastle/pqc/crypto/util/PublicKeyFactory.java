package org.bouncycastle.pqc.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.asn1.SPHINCS256KeyParams;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.asn1.XMSSMTKeyParams;
import org.bouncycastle.pqc.asn1.XMSSPublicKey;
import org.bouncycastle.pqc.crypto.lms.HSSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.sphincs.SPHINCSPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class PublicKeyFactory {
  private static Map converters = new HashMap<Object, Object>();
  
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
  
  static {
    converters.put(PQCObjectIdentifiers.qTESLA_p_I, new QTeslaConverter());
    converters.put(PQCObjectIdentifiers.qTESLA_p_III, new QTeslaConverter());
    converters.put(PQCObjectIdentifiers.sphincs256, new SPHINCSConverter());
    converters.put(PQCObjectIdentifiers.newHope, new NHConverter());
    converters.put(PQCObjectIdentifiers.xmss, new XMSSConverter());
    converters.put(PQCObjectIdentifiers.xmss_mt, new XMSSMTConverter());
    converters.put(IsaraObjectIdentifiers.id_alg_xmss, new XMSSConverter());
    converters.put(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTConverter());
    converters.put(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSConverter());
    converters.put(PQCObjectIdentifiers.mcElieceCca2, new McElieceCCA2Converter());
  }
  
  private static class LMSConverter extends SubjectPublicKeyInfoConverter {
    private LMSConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      byte[] arrayOfByte = ASN1OctetString.getInstance(param1SubjectPublicKeyInfo.parsePublicKey()).getOctets();
      if (Pack.bigEndianToInt(arrayOfByte, 0) == 1)
        return LMSPublicKeyParameters.getInstance(Arrays.copyOfRange(arrayOfByte, 4, arrayOfByte.length)); 
      if (arrayOfByte.length == 64)
        arrayOfByte = Arrays.copyOfRange(arrayOfByte, 4, arrayOfByte.length); 
      return HSSPublicKeyParameters.getInstance(arrayOfByte);
    }
  }
  
  private static class McElieceCCA2Converter extends SubjectPublicKeyInfoConverter {
    private McElieceCCA2Converter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      McElieceCCA2PublicKey mcElieceCCA2PublicKey = McElieceCCA2PublicKey.getInstance(param1SubjectPublicKeyInfo.parsePublicKey());
      return new McElieceCCA2PublicKeyParameters(mcElieceCCA2PublicKey.getN(), mcElieceCCA2PublicKey.getT(), mcElieceCCA2PublicKey.getG(), Utils.getDigestName(mcElieceCCA2PublicKey.getDigest().getAlgorithm()));
    }
  }
  
  private static class NHConverter extends SubjectPublicKeyInfoConverter {
    private NHConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      return new NHPublicKeyParameters(param1SubjectPublicKeyInfo.getPublicKeyData().getBytes());
    }
  }
  
  private static class QTeslaConverter extends SubjectPublicKeyInfoConverter {
    private QTeslaConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      return new QTESLAPublicKeyParameters(Utils.qTeslaLookupSecurityCategory(param1SubjectPublicKeyInfo.getAlgorithm()), param1SubjectPublicKeyInfo.getPublicKeyData().getOctets());
    }
  }
  
  private static class SPHINCSConverter extends SubjectPublicKeyInfoConverter {
    private SPHINCSConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      return new SPHINCSPublicKeyParameters(param1SubjectPublicKeyInfo.getPublicKeyData().getBytes(), Utils.sphincs256LookupTreeAlgName(SPHINCS256KeyParams.getInstance(param1SubjectPublicKeyInfo.getAlgorithm().getParameters())));
    }
  }
  
  private static abstract class SubjectPublicKeyInfoConverter {
    private SubjectPublicKeyInfoConverter() {}
    
    abstract AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException;
  }
  
  private static class XMSSConverter extends SubjectPublicKeyInfoConverter {
    private XMSSConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      XMSSKeyParams xMSSKeyParams = XMSSKeyParams.getInstance(param1SubjectPublicKeyInfo.getAlgorithm().getParameters());
      if (xMSSKeyParams != null) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = xMSSKeyParams.getTreeDigest().getAlgorithm();
        XMSSPublicKey xMSSPublicKey = XMSSPublicKey.getInstance(param1SubjectPublicKeyInfo.parsePublicKey());
        return (new XMSSPublicKeyParameters.Builder(new XMSSParameters(xMSSKeyParams.getHeight(), Utils.getDigest(aSN1ObjectIdentifier)))).withPublicSeed(xMSSPublicKey.getPublicSeed()).withRoot(xMSSPublicKey.getRoot()).build();
      } 
      byte[] arrayOfByte = ASN1OctetString.getInstance(param1SubjectPublicKeyInfo.parsePublicKey()).getOctets();
      return (new XMSSPublicKeyParameters.Builder(XMSSParameters.lookupByOID(Pack.bigEndianToInt(arrayOfByte, 0)))).withPublicKey(arrayOfByte).build();
    }
  }
  
  private static class XMSSMTConverter extends SubjectPublicKeyInfoConverter {
    private XMSSMTConverter() {}
    
    AsymmetricKeyParameter getPublicKeyParameters(SubjectPublicKeyInfo param1SubjectPublicKeyInfo, Object param1Object) throws IOException {
      XMSSMTKeyParams xMSSMTKeyParams = XMSSMTKeyParams.getInstance(param1SubjectPublicKeyInfo.getAlgorithm().getParameters());
      if (xMSSMTKeyParams != null) {
        ASN1ObjectIdentifier aSN1ObjectIdentifier = xMSSMTKeyParams.getTreeDigest().getAlgorithm();
        XMSSPublicKey xMSSPublicKey = XMSSPublicKey.getInstance(param1SubjectPublicKeyInfo.parsePublicKey());
        return (new XMSSMTPublicKeyParameters.Builder(new XMSSMTParameters(xMSSMTKeyParams.getHeight(), xMSSMTKeyParams.getLayers(), Utils.getDigest(aSN1ObjectIdentifier)))).withPublicSeed(xMSSPublicKey.getPublicSeed()).withRoot(xMSSPublicKey.getRoot()).build();
      } 
      byte[] arrayOfByte = ASN1OctetString.getInstance(param1SubjectPublicKeyInfo.parsePublicKey()).getOctets();
      return (new XMSSMTPublicKeyParameters.Builder(XMSSMTParameters.lookupByOID(Pack.bigEndianToInt(arrayOfByte, 0)))).withPublicKey(arrayOfByte).build();
    }
  }
}
