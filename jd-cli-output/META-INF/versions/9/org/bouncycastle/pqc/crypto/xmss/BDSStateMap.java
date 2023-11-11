package META-INF.versions.9.org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Map;
import java.util.TreeMap;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.pqc.crypto.xmss.BDS;
import org.bouncycastle.pqc.crypto.xmss.OTSHashAddress;
import org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSParameters;
import org.bouncycastle.pqc.crypto.xmss.XMSSUtil;
import org.bouncycastle.util.Integers;

public class BDSStateMap implements Serializable {
  private static final long serialVersionUID = -3464451825208522308L;
  
  private final Map<Integer, BDS> bdsState = new TreeMap<>();
  
  private transient long maxIndex;
  
  BDSStateMap(long paramLong) {
    this.maxIndex = paramLong;
  }
  
  BDSStateMap(org.bouncycastle.pqc.crypto.xmss.BDSStateMap paramBDSStateMap, long paramLong) {
    for (Integer integer : paramBDSStateMap.bdsState.keySet())
      this.bdsState.put(integer, new BDS(paramBDSStateMap.bdsState.get(integer))); 
    this.maxIndex = paramLong;
  }
  
  BDSStateMap(XMSSMTParameters paramXMSSMTParameters, long paramLong, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    this.maxIndex = (1L << paramXMSSMTParameters.getHeight()) - 1L;
    long l;
    for (l = 0L; l < paramLong; l++)
      updateState(paramXMSSMTParameters, l, paramArrayOfbyte1, paramArrayOfbyte2); 
  }
  
  public long getMaxIndex() {
    return this.maxIndex;
  }
  
  void updateState(XMSSMTParameters paramXMSSMTParameters, long paramLong, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    XMSSParameters xMSSParameters = paramXMSSMTParameters.getXMSSParameters();
    int i = xMSSParameters.getHeight();
    long l = XMSSUtil.getTreeIndex(paramLong, i);
    int j = XMSSUtil.getLeafIndex(paramLong, i);
    OTSHashAddress oTSHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withTreeAddress(l).withOTSAddress(j).build();
    if (j < (1 << i) - 1) {
      if (get(0) == null || j == 0)
        put(0, new BDS(xMSSParameters, paramArrayOfbyte1, paramArrayOfbyte2, oTSHashAddress)); 
      update(0, paramArrayOfbyte1, paramArrayOfbyte2, oTSHashAddress);
    } 
    for (byte b = 1; b < paramXMSSMTParameters.getLayers(); b++) {
      j = XMSSUtil.getLeafIndex(l, i);
      l = XMSSUtil.getTreeIndex(l, i);
      oTSHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(b).withTreeAddress(l).withOTSAddress(j).build();
      if (this.bdsState.get(Integer.valueOf(b)) == null || XMSSUtil.isNewBDSInitNeeded(paramLong, i, b))
        this.bdsState.put(Integer.valueOf(b), new BDS(xMSSParameters, paramArrayOfbyte1, paramArrayOfbyte2, oTSHashAddress)); 
      if (j < (1 << i) - 1 && 
        XMSSUtil.isNewAuthenticationPathNeeded(paramLong, i, b))
        update(b, paramArrayOfbyte1, paramArrayOfbyte2, oTSHashAddress); 
    } 
  }
  
  public boolean isEmpty() {
    return this.bdsState.isEmpty();
  }
  
  BDS get(int paramInt) {
    return this.bdsState.get(Integers.valueOf(paramInt));
  }
  
  BDS update(int paramInt, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, OTSHashAddress paramOTSHashAddress) {
    return this.bdsState.put(Integers.valueOf(paramInt), ((BDS)this.bdsState.get(Integers.valueOf(paramInt))).getNextState(paramArrayOfbyte1, paramArrayOfbyte2, paramOTSHashAddress));
  }
  
  void put(int paramInt, BDS paramBDS) {
    this.bdsState.put(Integers.valueOf(paramInt), paramBDS);
  }
  
  public org.bouncycastle.pqc.crypto.xmss.BDSStateMap withWOTSDigest(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    org.bouncycastle.pqc.crypto.xmss.BDSStateMap bDSStateMap = new org.bouncycastle.pqc.crypto.xmss.BDSStateMap(this.maxIndex);
    for (Integer integer : this.bdsState.keySet())
      bDSStateMap.bdsState.put(integer, ((BDS)this.bdsState.get(integer)).withWOTSDigest(paramASN1ObjectIdentifier)); 
    return bDSStateMap;
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    if (paramObjectInputStream.available() != 0) {
      this.maxIndex = paramObjectInputStream.readLong();
    } else {
      this.maxIndex = 0L;
    } 
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeLong(this.maxIndex);
  }
}
