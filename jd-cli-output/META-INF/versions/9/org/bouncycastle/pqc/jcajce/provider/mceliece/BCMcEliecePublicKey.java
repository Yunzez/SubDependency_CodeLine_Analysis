package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McEliecePublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class BCMcEliecePublicKey implements PublicKey {
  private static final long serialVersionUID = 1L;
  
  private McEliecePublicKeyParameters params;
  
  public BCMcEliecePublicKey(McEliecePublicKeyParameters paramMcEliecePublicKeyParameters) {
    this.params = paramMcEliecePublicKeyParameters;
  }
  
  public String getAlgorithm() {
    return "McEliece";
  }
  
  public int getN() {
    return this.params.getN();
  }
  
  public int getK() {
    return this.params.getK();
  }
  
  public int getT() {
    return this.params.getT();
  }
  
  public GF2Matrix getG() {
    return this.params.getG();
  }
  
  public String toString() {
    String str = "McEliecePublicKey:\n";
    str = str + " length of the code         : " + str + "\n";
    str = str + " error correction capability: " + str + "\n";
    str = str + " generator matrix           : " + str;
    return str;
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject instanceof org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey) {
      org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey bCMcEliecePublicKey = (org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey)paramObject;
      return (this.params.getN() == bCMcEliecePublicKey.getN() && this.params.getT() == bCMcEliecePublicKey.getT() && this.params.getG().equals(bCMcEliecePublicKey.getG()));
    } 
    return false;
  }
  
  public int hashCode() {
    return 37 * (this.params.getN() + 37 * this.params.getT()) + this.params.getG().hashCode();
  }
  
  public byte[] getEncoded() {
    McEliecePublicKey mcEliecePublicKey = new McEliecePublicKey(this.params.getN(), this.params.getT(), this.params.getG());
    AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcEliece);
    try {
      SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, mcEliecePublicKey);
      return subjectPublicKeyInfo.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public String getFormat() {
    return "X.509";
  }
  
  AsymmetricKeyParameter getKeyParams() {
    return this.params;
  }
}
