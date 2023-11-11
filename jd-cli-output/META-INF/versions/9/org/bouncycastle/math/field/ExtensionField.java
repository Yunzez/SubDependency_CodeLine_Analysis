package META-INF.versions.9.org.bouncycastle.math.field;

import org.bouncycastle.math.field.FiniteField;

public interface ExtensionField extends FiniteField {
  FiniteField getSubfield();
  
  int getDegree();
}
