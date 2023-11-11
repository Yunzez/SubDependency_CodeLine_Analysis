package org.bouncycastle.jcajce.provider.asymmetric;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.CompositePrivateKey;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.BaseKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricKeyInfoConverter;

public class COMPOSITE {
  private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE";
  
  private static final Map<String, String> compositeAttributes = new HashMap<String, String>();
  
  private static AsymmetricKeyInfoConverter baseConverter;
  
  static {
    compositeAttributes.put("SupportedKeyClasses", "org.bouncycastle.jcajce.CompositePublicKey|org.bouncycastle.jcajce.CompositePrivateKey");
    compositeAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
  }
  
  private static class CompositeKeyInfoConverter implements AsymmetricKeyInfoConverter {
    private final ConfigurableProvider provider;
    
    public CompositeKeyInfoConverter(ConfigurableProvider param1ConfigurableProvider) {
      this.provider = param1ConfigurableProvider;
    }
    
    public PrivateKey generatePrivate(PrivateKeyInfo param1PrivateKeyInfo) throws IOException {
      ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(param1PrivateKeyInfo.getPrivateKey().getOctets());
      PrivateKey[] arrayOfPrivateKey = new PrivateKey[aSN1Sequence.size()];
      for (byte b = 0; b != aSN1Sequence.size(); b++) {
        PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(aSN1Sequence.getObjectAt(b));
        arrayOfPrivateKey[b] = this.provider.getKeyInfoConverter(privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm()).generatePrivate(privateKeyInfo);
      } 
      return new CompositePrivateKey(arrayOfPrivateKey);
    }
    
    public PublicKey generatePublic(SubjectPublicKeyInfo param1SubjectPublicKeyInfo) throws IOException {
      ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(param1SubjectPublicKeyInfo.getPublicKeyData().getBytes());
      PublicKey[] arrayOfPublicKey = new PublicKey[aSN1Sequence.size()];
      for (byte b = 0; b != aSN1Sequence.size(); b++) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(aSN1Sequence.getObjectAt(b));
        arrayOfPublicKey[b] = this.provider.getKeyInfoConverter(subjectPublicKeyInfo.getAlgorithm().getAlgorithm()).generatePublic(subjectPublicKeyInfo);
      } 
      return new CompositePublicKey(arrayOfPublicKey);
    }
  }
  
  public static class KeyFactory extends BaseKeyFactorySpi {
    protected Key engineTranslateKey(Key param1Key) throws InvalidKeyException {
      try {
        if (param1Key instanceof PrivateKey)
          return generatePrivate(PrivateKeyInfo.getInstance(param1Key.getEncoded())); 
        if (param1Key instanceof PublicKey)
          return generatePublic(SubjectPublicKeyInfo.getInstance(param1Key.getEncoded())); 
      } catch (IOException iOException) {
        throw new InvalidKeyException("key could not be parsed: " + iOException.getMessage());
      } 
      throw new InvalidKeyException("key not recognized");
    }
    
    public PrivateKey generatePrivate(PrivateKeyInfo param1PrivateKeyInfo) throws IOException {
      return COMPOSITE.baseConverter.generatePrivate(param1PrivateKeyInfo);
    }
    
    public PublicKey generatePublic(SubjectPublicKeyInfo param1SubjectPublicKeyInfo) throws IOException {
      return COMPOSITE.baseConverter.generatePublic(param1SubjectPublicKeyInfo);
    }
  }
  
  public static class Mappings extends AsymmetricAlgorithmProvider {
    public void configure(ConfigurableProvider param1ConfigurableProvider) {
      param1ConfigurableProvider.addAlgorithm("KeyFactory.COMPOSITE", "org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE$KeyFactory");
      param1ConfigurableProvider.addAlgorithm("KeyFactory." + MiscObjectIdentifiers.id_alg_composite, "org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE$KeyFactory");
      param1ConfigurableProvider.addAlgorithm("KeyFactory.OID." + MiscObjectIdentifiers.id_alg_composite, "org.bouncycastle.jcajce.provider.asymmetric.COMPOSITE$KeyFactory");
      COMPOSITE.baseConverter = new COMPOSITE.CompositeKeyInfoConverter(param1ConfigurableProvider);
      param1ConfigurableProvider.addKeyInfoConverter(MiscObjectIdentifiers.id_alg_composite, COMPOSITE.baseConverter);
    }
  }
}
