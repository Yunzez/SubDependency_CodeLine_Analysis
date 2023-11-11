package META-INF.versions.9.org.bouncycastle.pqc.jcajce.interfaces;

public interface XMSSMTKey {
  int getHeight();
  
  int getLayers();
  
  String getTreeDigest();
}
