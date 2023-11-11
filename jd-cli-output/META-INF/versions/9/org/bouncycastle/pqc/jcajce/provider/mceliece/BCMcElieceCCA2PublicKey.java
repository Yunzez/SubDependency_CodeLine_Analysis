package META-INF.versions.9.org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.io.IOException;
import java.security.PublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.asn1.McElieceCCA2PublicKey;
import org.bouncycastle.pqc.asn1.PQCObjectIdentifiers;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCCA2PublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.mceliece.Utils;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

public class BCMcElieceCCA2PublicKey implements CipherParameters, PublicKey {
  private static final long serialVersionUID = 1L;
  
  private McElieceCCA2PublicKeyParameters params;
  
  public BCMcElieceCCA2PublicKey(McElieceCCA2PublicKeyParameters paramMcElieceCCA2PublicKeyParameters) {
    this.params = paramMcElieceCCA2PublicKeyParameters;
  }
  
  public String getAlgorithm() {
    return "McEliece-CCA2";
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
    if (paramObject == null || !(paramObject instanceof org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey))
      return false; 
    org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey bCMcElieceCCA2PublicKey = (org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey)paramObject;
    return (this.params.getN() == bCMcElieceCCA2PublicKey.getN() && this.params.getT() == bCMcElieceCCA2PublicKey.getT() && this.params.getG().equals(bCMcElieceCCA2PublicKey.getG()));
  }
  
  public int hashCode() {
    return 37 * (this.params.getN() + 37 * this.params.getT()) + this.params.getG().hashCode();
  }
  
  public byte[] getEncoded() {
    McElieceCCA2PublicKey mcElieceCCA2PublicKey = new McElieceCCA2PublicKey(this.params.getN(), this.params.getT(), this.params.getG(), Utils.getDigAlgId(this.params.getDigest()));
    AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(PQCObjectIdentifiers.mcElieceCca2);
    try {
      SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(algorithmIdentifier, mcElieceCCA2PublicKey);
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
