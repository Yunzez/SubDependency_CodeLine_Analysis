package org.bouncycastle.pqc.jcajce.provider.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PrivateKey;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.asn1.XMSSKeyParams;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters;
import org.bouncycastle.pqc.jcajce.interfaces.XMSSPrivateKey;
import org.bouncycastle.util.Arrays;

public class BCXMSSPrivateKey implements PrivateKey, XMSSPrivateKey {
  private static final long serialVersionUID = 8568701712864512338L;
  
  private transient XMSSPrivateKeyParameters keyParams;
  
  private transient ASN1ObjectIdentifier treeDigest;
  
  private transient ASN1Set attributes;
  
  public BCXMSSPrivateKey(ASN1ObjectIdentifier paramASN1ObjectIdentifier, XMSSPrivateKeyParameters paramXMSSPrivateKeyParameters) {
    this.treeDigest = paramASN1ObjectIdentifier;
    this.keyParams = paramXMSSPrivateKeyParameters;
  }
  
  public BCXMSSPrivateKey(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    init(paramPrivateKeyInfo);
  }
  
  private void init(PrivateKeyInfo paramPrivateKeyInfo) throws IOException {
    this.attributes = paramPrivateKeyInfo.getAttributes();
    XMSSKeyParams xMSSKeyParams = XMSSKeyParams.getInstance(paramPrivateKeyInfo.getPrivateKeyAlgorithm().getParameters());
    this.treeDigest = xMSSKeyParams.getTreeDigest().getAlgorithm();
    this.keyParams = (XMSSPrivateKeyParameters)PrivateKeyFactory.createKey(paramPrivateKeyInfo);
  }
  
  public long getIndex() {
    if (getUsagesRemaining() == 0L)
      throw new IllegalStateException("key exhausted"); 
    return this.keyParams.getIndex();
  }
  
  public long getUsagesRemaining() {
    return this.keyParams.getUsagesRemaining();
  }
  
  public XMSSPrivateKey extractKeyShard(int paramInt) {
    return new BCXMSSPrivateKey(this.treeDigest, this.keyParams.extractKeyShard(paramInt));
  }
  
  public String getAlgorithm() {
    return "XMSS";
  }
  
  public String getFormat() {
    return "PKCS#8";
  }
  
  public byte[] getEncoded() {
    try {
      PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(this.keyParams, this.attributes);
      return privateKeyInfo.getEncoded();
    } catch (IOException iOException) {
      return null;
    } 
  }
  
  public boolean equals(Object paramObject) {
    if (paramObject == this)
      return true; 
    if (paramObject instanceof BCXMSSPrivateKey) {
      BCXMSSPrivateKey bCXMSSPrivateKey = (BCXMSSPrivateKey)paramObject;
      return (this.treeDigest.equals(bCXMSSPrivateKey.treeDigest) && Arrays.areEqual(this.keyParams.toByteArray(), bCXMSSPrivateKey.keyParams.toByteArray()));
    } 
    return false;
  }
  
  public int hashCode() {
    return this.treeDigest.hashCode() + 37 * Arrays.hashCode(this.keyParams.toByteArray());
  }
  
  CipherParameters getKeyParams() {
    return this.keyParams;
  }
  
  ASN1ObjectIdentifier getTreeDigestOID() {
    return this.treeDigest;
  }
  
  public int getHeight() {
    return this.keyParams.getParameters().getHeight();
  }
  
  public String getTreeDigest() {
    return DigestUtil.getXMSSDigestName(this.treeDigest);
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    byte[] arrayOfByte = (byte[])paramObjectInputStream.readObject();
    init(PrivateKeyInfo.getInstance(arrayOfByte));
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeObject(getEncoded());
  }
}
