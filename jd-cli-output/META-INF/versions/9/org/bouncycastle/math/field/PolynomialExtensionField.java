package META-INF.versions.9.org.bouncycastle.math.field;

import org.bouncycastle.math.field.ExtensionField;
import org.bouncycastle.math.field.Polynomial;

public interface PolynomialExtensionField extends ExtensionField {
  Polynomial getMinimalPolynomial();
}
