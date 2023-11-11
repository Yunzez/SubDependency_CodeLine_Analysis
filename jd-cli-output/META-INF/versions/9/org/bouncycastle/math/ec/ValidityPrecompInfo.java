package META-INF.versions.9.org.bouncycastle.math.ec;

import org.bouncycastle.math.ec.PreCompInfo;

class ValidityPrecompInfo implements PreCompInfo {
  static final String PRECOMP_NAME = "bc_validity";
  
  private boolean failed = false;
  
  private boolean curveEquationPassed = false;
  
  private boolean orderPassed = false;
  
  boolean hasFailed() {
    return this.failed;
  }
  
  void reportFailed() {
    this.failed = true;
  }
  
  boolean hasCurveEquationPassed() {
    return this.curveEquationPassed;
  }
  
  void reportCurveEquationPassed() {
    this.curveEquationPassed = true;
  }
  
  boolean hasOrderPassed() {
    return this.orderPassed;
  }
  
  void reportOrderPassed() {
    this.orderPassed = true;
  }
}
