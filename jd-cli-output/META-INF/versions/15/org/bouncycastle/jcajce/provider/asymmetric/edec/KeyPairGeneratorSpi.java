package META-INF.versions.15.org.bouncycastle.jcajce.provider.asymmetric.edec;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.generators.X448KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X448KeyGenerationParameters;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC11XDHPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC11XDHPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC15EdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BC15EdDSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveGenParameterSpec;

public class KeyPairGeneratorSpi extends KeyPairGeneratorSpi {
  private static final int EdDSA = -1;
  
  private static final int XDH = -2;
  
  private static final int Ed25519 = 1;
  
  private static final int Ed448 = 2;
  
  private static final int X25519 = 3;
  
  private static final int X448 = 4;
  
  private final int algorithmDeclared;
  
  private int algorithmInitialized;
  
  private SecureRandom secureRandom;
  
  private AsymmetricCipherKeyPairGenerator generator;
  
  KeyPairGeneratorSpi(int paramInt) {
    this.algorithmDeclared = paramInt;
    if (getAlgorithmFamily(paramInt) != paramInt)
      this.algorithmInitialized = paramInt; 
  }
  
  public void initialize(int paramInt, SecureRandom paramSecureRandom) {
    int i = getAlgorithmForStrength(paramInt);
    this.algorithmInitialized = i;
    this.secureRandom = paramSecureRandom;
    this.generator = null;
  }
  
  public void initialize(AlgorithmParameterSpec paramAlgorithmParameterSpec, SecureRandom paramSecureRandom) throws InvalidAlgorithmParameterException {
    String str = getNameFromParams(paramAlgorithmParameterSpec);
    if (null == str)
      throw new InvalidAlgorithmParameterException("invalid parameterSpec: " + paramAlgorithmParameterSpec); 
    int i = getAlgorithmForName(str);
    if (this.algorithmDeclared != i && this.algorithmDeclared != 
      getAlgorithmFamily(i))
      throw new InvalidAlgorithmParameterException("parameterSpec for wrong curve type"); 
    this.algorithmInitialized = i;
    this.secureRandom = paramSecureRandom;
    this.generator = null;
  }
  
  public KeyPair generateKeyPair() {
    if (this.algorithmInitialized == 0)
      throw new IllegalStateException("generator not correctly initialized"); 
    if (null == this.generator)
      this.generator = setupGenerator(); 
    AsymmetricCipherKeyPair asymmetricCipherKeyPair = this.generator.generateKeyPair();
    switch (this.algorithmInitialized) {
      case 1:
      case 2:
        return new KeyPair((PublicKey)new BC15EdDSAPublicKey(asymmetricCipherKeyPair.getPublic()), (PrivateKey)new BC15EdDSAPrivateKey(asymmetricCipherKeyPair.getPrivate()));
      case 3:
      case 4:
        return new KeyPair((PublicKey)new BC11XDHPublicKey(asymmetricCipherKeyPair.getPublic()), (PrivateKey)new BC11XDHPrivateKey(asymmetricCipherKeyPair.getPrivate()));
    } 
    throw new IllegalStateException("generator not correctly initialized");
  }
  
  private int getAlgorithmForStrength(int paramInt) {
    switch (paramInt) {
      case 255:
      case 256:
        switch (this.algorithmDeclared) {
          case -1:
          case 1:
            return 1;
          case -2:
          case 3:
            return 3;
        } 
        throw new InvalidParameterException("key size not configurable");
      case 448:
        switch (this.algorithmDeclared) {
          case -1:
          case 2:
            return 2;
          case -2:
          case 4:
            return 4;
        } 
        throw new InvalidParameterException("key size not configurable");
    } 
    throw new InvalidParameterException("unknown key size");
  }
  
  private AsymmetricCipherKeyPairGenerator setupGenerator() {
    Ed25519KeyPairGenerator ed25519KeyPairGenerator;
    Ed448KeyPairGenerator ed448KeyPairGenerator;
    X25519KeyPairGenerator x25519KeyPairGenerator;
    X448KeyPairGenerator x448KeyPairGenerator;
    if (null == this.secureRandom)
      this.secureRandom = CryptoServicesRegistrar.getSecureRandom(); 
    switch (this.algorithmInitialized) {
      case 1:
        ed25519KeyPairGenerator = new Ed25519KeyPairGenerator();
        ed25519KeyPairGenerator.init(new Ed25519KeyGenerationParameters(this.secureRandom));
        return ed25519KeyPairGenerator;
      case 2:
        ed448KeyPairGenerator = new Ed448KeyPairGenerator();
        ed448KeyPairGenerator.init(new Ed448KeyGenerationParameters(this.secureRandom));
        return ed448KeyPairGenerator;
      case 3:
        x25519KeyPairGenerator = new X25519KeyPairGenerator();
        x25519KeyPairGenerator.init(new X25519KeyGenerationParameters(this.secureRandom));
        return x25519KeyPairGenerator;
      case 4:
        x448KeyPairGenerator = new X448KeyPairGenerator();
        x448KeyPairGenerator.init(new X448KeyGenerationParameters(this.secureRandom));
        return x448KeyPairGenerator;
    } 
    throw new IllegalStateException("generator not correctly initialized");
  }
  
  private static int getAlgorithmFamily(int paramInt) {
    switch (paramInt) {
      case 1:
      case 2:
        return -1;
      case 3:
      case 4:
        return -2;
    } 
    return paramInt;
  }
  
  private static int getAlgorithmForName(String paramString) throws InvalidAlgorithmParameterException {
    if (paramString.equalsIgnoreCase("X25519") || paramString.equals(EdECObjectIdentifiers.id_X25519.getId()))
      return 3; 
    if (paramString.equalsIgnoreCase("Ed25519") || paramString.equals(EdECObjectIdentifiers.id_Ed25519.getId()))
      return 1; 
    if (paramString.equalsIgnoreCase("X448") || paramString.equals(EdECObjectIdentifiers.id_X448.getId()))
      return 4; 
    if (paramString.equalsIgnoreCase("Ed448") || paramString.equals(EdECObjectIdentifiers.id_Ed448.getId()))
      return 2; 
    throw new InvalidAlgorithmParameterException("invalid parameterSpec name: " + paramString);
  }
  
  private static String getNameFromParams(AlgorithmParameterSpec paramAlgorithmParameterSpec) throws InvalidAlgorithmParameterException {
    if (paramAlgorithmParameterSpec instanceof ECGenParameterSpec)
      return ((ECGenParameterSpec)paramAlgorithmParameterSpec).getName(); 
    if (paramAlgorithmParameterSpec instanceof ECNamedCurveGenParameterSpec)
      return ((ECNamedCurveGenParameterSpec)paramAlgorithmParameterSpec).getName(); 
    if (paramAlgorithmParameterSpec instanceof NamedParameterSpec)
      return ((NamedParameterSpec)paramAlgorithmParameterSpec).getName(); 
    if (paramAlgorithmParameterSpec instanceof EdDSAParameterSpec)
      return ((EdDSAParameterSpec)paramAlgorithmParameterSpec).getCurveName(); 
    if (paramAlgorithmParameterSpec instanceof XDHParameterSpec)
      return ((XDHParameterSpec)paramAlgorithmParameterSpec).getCurveName(); 
    return ECUtil.getNameFrom(paramAlgorithmParameterSpec);
  }
}
