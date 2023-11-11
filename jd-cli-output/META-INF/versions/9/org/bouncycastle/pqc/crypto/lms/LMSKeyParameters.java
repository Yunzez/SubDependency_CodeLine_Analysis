package META-INF.versions.9.org.bouncycastle.pqc.crypto.lms;

import java.io.IOException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Encodable;

public abstract class LMSKeyParameters extends AsymmetricKeyParameter implements Encodable {
  protected LMSKeyParameters(boolean paramBoolean) {
    super(paramBoolean);
  }
  
  public abstract byte[] getEncoded() throws IOException;
}
