package META-INF.versions.9.org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;

public class QTESLAParameterSpec implements AlgorithmParameterSpec {
  public static final String PROVABLY_SECURE_I = QTESLASecurityCategory.getName(5);
  
  public static final String PROVABLY_SECURE_III = QTESLASecurityCategory.getName(6);
  
  private String securityCategory;
  
  public QTESLAParameterSpec(String paramString) {
    this.securityCategory = paramString;
  }
  
  public String getSecurityCategory() {
    return this.securityCategory;
  }
}
