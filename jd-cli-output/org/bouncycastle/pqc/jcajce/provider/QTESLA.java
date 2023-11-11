package org.bouncycastle.pqc.jcajce.provider;

import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi;

public class QTESLA {
  private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.qtesla.";
  
  public static class Mappings extends AsymmetricAlgorithmProvider {
    public void configure(ConfigurableProvider param1ConfigurableProvider) {
      param1ConfigurableProvider.addAlgorithm("KeyFactory.QTESLA", "org.bouncycastle.pqc.jcajce.provider.qtesla.QTESLAKeyFactorySpi");
      param1ConfigurableProvider.addAlgorithm("KeyPairGenerator.QTESLA", "org.bouncycastle.pqc.jcajce.provider.qtesla.KeyPairGeneratorSpi");
      param1ConfigurableProvider.addAlgorithm("Signature.QTESLA", "org.bouncycastle.pqc.jcajce.provider.qtesla.SignatureSpi$qTESLA");
      addSignatureAlgorithm(param1ConfigurableProvider, "QTESLA-P-I", "org.bouncycastle.pqc.jcajce.provider.qtesla.SignatureSpi$PI", PQCObjectIdentifiers.qTESLA_p_I);
      addSignatureAlgorithm(param1ConfigurableProvider, "QTESLA-P-III", "org.bouncycastle.pqc.jcajce.provider.qtesla.SignatureSpi$PIII", PQCObjectIdentifiers.qTESLA_p_III);
      QTESLAKeyFactorySpi qTESLAKeyFactorySpi = new QTESLAKeyFactorySpi();
      registerOid(param1ConfigurableProvider, PQCObjectIdentifiers.qTESLA_p_I, "QTESLA-P-I", qTESLAKeyFactorySpi);
      registerOid(param1ConfigurableProvider, PQCObjectIdentifiers.qTESLA_p_III, "QTESLA-P-III", qTESLAKeyFactorySpi);
    }
  }
}
