package org.bouncycastle.pqc.crypto.xmss;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Stack;
import java.util.TreeMap;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

public final class BDS implements Serializable {
  private static final long serialVersionUID = 1L;
  
  private transient WOTSPlus wotsPlus;
  
  private final int treeHeight;
  
  private final List<BDSTreeHash> treeHashInstances;
  
  private int k;
  
  private XMSSNode root;
  
  private List<XMSSNode> authenticationPath;
  
  private Map<Integer, LinkedList<XMSSNode>> retain;
  
  private Stack<XMSSNode> stack;
  
  private Map<Integer, XMSSNode> keep;
  
  private int index;
  
  private boolean used;
  
  private transient int maxIndex;
  
  BDS(XMSSParameters paramXMSSParameters, int paramInt1, int paramInt2) {
    this(paramXMSSParameters.getWOTSPlus(), paramXMSSParameters.getHeight(), paramXMSSParameters.getK(), paramInt2);
    this.maxIndex = paramInt1;
    this.index = paramInt2;
    this.used = true;
  }
  
  BDS(XMSSParameters paramXMSSParameters, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, OTSHashAddress paramOTSHashAddress) {
    this(paramXMSSParameters.getWOTSPlus(), paramXMSSParameters.getHeight(), paramXMSSParameters.getK(), (1 << paramXMSSParameters.getHeight()) - 1);
    initialize(paramArrayOfbyte1, paramArrayOfbyte2, paramOTSHashAddress);
  }
  
  BDS(XMSSParameters paramXMSSParameters, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, OTSHashAddress paramOTSHashAddress, int paramInt) {
    this(paramXMSSParameters.getWOTSPlus(), paramXMSSParameters.getHeight(), paramXMSSParameters.getK(), (1 << paramXMSSParameters.getHeight()) - 1);
    initialize(paramArrayOfbyte1, paramArrayOfbyte2, paramOTSHashAddress);
    while (this.index < paramInt) {
      nextAuthenticationPath(paramArrayOfbyte1, paramArrayOfbyte2, paramOTSHashAddress);
      this.used = false;
    } 
  }
  
  private BDS(WOTSPlus paramWOTSPlus, int paramInt1, int paramInt2, int paramInt3) {
    this.wotsPlus = paramWOTSPlus;
    this.treeHeight = paramInt1;
    this.maxIndex = paramInt3;
    this.k = paramInt2;
    if (paramInt2 > paramInt1 || paramInt2 < 2 || (paramInt1 - paramInt2) % 2 != 0)
      throw new IllegalArgumentException("illegal value for BDS parameter k"); 
    this.authenticationPath = new ArrayList<XMSSNode>();
    this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
    this.stack = new Stack<XMSSNode>();
    this.treeHashInstances = new ArrayList<BDSTreeHash>();
    for (byte b = 0; b < paramInt1 - paramInt2; b++)
      this.treeHashInstances.add(new BDSTreeHash(b)); 
    this.keep = new TreeMap<Integer, XMSSNode>();
    this.index = 0;
    this.used = false;
  }
  
  BDS(BDS paramBDS) {
    this.wotsPlus = new WOTSPlus(paramBDS.wotsPlus.getParams());
    this.treeHeight = paramBDS.treeHeight;
    this.k = paramBDS.k;
    this.root = paramBDS.root;
    this.authenticationPath = new ArrayList<XMSSNode>();
    this.authenticationPath.addAll(paramBDS.authenticationPath);
    this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
    for (Integer integer : paramBDS.retain.keySet())
      this.retain.put(integer, (LinkedList<XMSSNode>)((LinkedList)paramBDS.retain.get(integer)).clone()); 
    this.stack = new Stack<XMSSNode>();
    this.stack.addAll(paramBDS.stack);
    this.treeHashInstances = new ArrayList<BDSTreeHash>();
    Iterator<BDSTreeHash> iterator = paramBDS.treeHashInstances.iterator();
    while (iterator.hasNext())
      this.treeHashInstances.add(((BDSTreeHash)iterator.next()).clone()); 
    this.keep = new TreeMap<Integer, XMSSNode>(paramBDS.keep);
    this.index = paramBDS.index;
    this.maxIndex = paramBDS.maxIndex;
    this.used = paramBDS.used;
  }
  
  private BDS(BDS paramBDS, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, OTSHashAddress paramOTSHashAddress) {
    this.wotsPlus = new WOTSPlus(paramBDS.wotsPlus.getParams());
    this.treeHeight = paramBDS.treeHeight;
    this.k = paramBDS.k;
    this.root = paramBDS.root;
    this.authenticationPath = new ArrayList<XMSSNode>();
    this.authenticationPath.addAll(paramBDS.authenticationPath);
    this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
    for (Integer integer : paramBDS.retain.keySet())
      this.retain.put(integer, (LinkedList<XMSSNode>)((LinkedList)paramBDS.retain.get(integer)).clone()); 
    this.stack = new Stack<XMSSNode>();
    this.stack.addAll(paramBDS.stack);
    this.treeHashInstances = new ArrayList<BDSTreeHash>();
    Iterator<BDSTreeHash> iterator = paramBDS.treeHashInstances.iterator();
    while (iterator.hasNext())
      this.treeHashInstances.add(((BDSTreeHash)iterator.next()).clone()); 
    this.keep = new TreeMap<Integer, XMSSNode>(paramBDS.keep);
    this.index = paramBDS.index;
    this.maxIndex = paramBDS.maxIndex;
    this.used = false;
    nextAuthenticationPath(paramArrayOfbyte1, paramArrayOfbyte2, paramOTSHashAddress);
  }
  
  private BDS(BDS paramBDS, ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    this.wotsPlus = new WOTSPlus(new WOTSPlusParameters(paramASN1ObjectIdentifier));
    this.treeHeight = paramBDS.treeHeight;
    this.k = paramBDS.k;
    this.root = paramBDS.root;
    this.authenticationPath = new ArrayList<XMSSNode>();
    this.authenticationPath.addAll(paramBDS.authenticationPath);
    this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
    for (Integer integer : paramBDS.retain.keySet())
      this.retain.put(integer, (LinkedList<XMSSNode>)((LinkedList)paramBDS.retain.get(integer)).clone()); 
    this.stack = new Stack<XMSSNode>();
    this.stack.addAll(paramBDS.stack);
    this.treeHashInstances = new ArrayList<BDSTreeHash>();
    Iterator<BDSTreeHash> iterator = paramBDS.treeHashInstances.iterator();
    while (iterator.hasNext())
      this.treeHashInstances.add(((BDSTreeHash)iterator.next()).clone()); 
    this.keep = new TreeMap<Integer, XMSSNode>(paramBDS.keep);
    this.index = paramBDS.index;
    this.maxIndex = paramBDS.maxIndex;
    this.used = paramBDS.used;
    validate();
  }
  
  private BDS(BDS paramBDS, int paramInt, ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    this.wotsPlus = new WOTSPlus(new WOTSPlusParameters(paramASN1ObjectIdentifier));
    this.treeHeight = paramBDS.treeHeight;
    this.k = paramBDS.k;
    this.root = paramBDS.root;
    this.authenticationPath = new ArrayList<XMSSNode>();
    this.authenticationPath.addAll(paramBDS.authenticationPath);
    this.retain = new TreeMap<Integer, LinkedList<XMSSNode>>();
    for (Integer integer : paramBDS.retain.keySet())
      this.retain.put(integer, (LinkedList<XMSSNode>)((LinkedList)paramBDS.retain.get(integer)).clone()); 
    this.stack = new Stack<XMSSNode>();
    this.stack.addAll(paramBDS.stack);
    this.treeHashInstances = new ArrayList<BDSTreeHash>();
    Iterator<BDSTreeHash> iterator = paramBDS.treeHashInstances.iterator();
    while (iterator.hasNext())
      this.treeHashInstances.add(((BDSTreeHash)iterator.next()).clone()); 
    this.keep = new TreeMap<Integer, XMSSNode>(paramBDS.keep);
    this.index = paramBDS.index;
    this.maxIndex = paramInt;
    this.used = paramBDS.used;
    validate();
  }
  
  public BDS getNextState(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, OTSHashAddress paramOTSHashAddress) {
    return new BDS(this, paramArrayOfbyte1, paramArrayOfbyte2, paramOTSHashAddress);
  }
  
  private void initialize(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, OTSHashAddress paramOTSHashAddress) {
    if (paramOTSHashAddress == null)
      throw new NullPointerException("otsHashAddress == null"); 
    LTreeAddress lTreeAddress = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(paramOTSHashAddress.getLayerAddress()).withTreeAddress(paramOTSHashAddress.getTreeAddress()).build();
    HashTreeAddress hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(paramOTSHashAddress.getLayerAddress()).withTreeAddress(paramOTSHashAddress.getTreeAddress()).build();
    for (byte b = 0; b < 1 << this.treeHeight; b++) {
      paramOTSHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(paramOTSHashAddress.getLayerAddress()).withTreeAddress(paramOTSHashAddress.getTreeAddress()).withOTSAddress(b).withChainAddress(paramOTSHashAddress.getChainAddress()).withHashAddress(paramOTSHashAddress.getHashAddress()).withKeyAndMask(paramOTSHashAddress.getKeyAndMask()).build();
      this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(paramArrayOfbyte2, paramOTSHashAddress), paramArrayOfbyte1);
      WOTSPlusPublicKeyParameters wOTSPlusPublicKeyParameters = this.wotsPlus.getPublicKey(paramOTSHashAddress);
      lTreeAddress = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(lTreeAddress.getLayerAddress()).withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(b).withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex()).withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
      XMSSNode xMSSNode = XMSSNodeUtil.lTree(this.wotsPlus, wOTSPlusPublicKeyParameters, lTreeAddress);
      for (hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeIndex(b).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build(); !this.stack.isEmpty() && ((XMSSNode)this.stack.peek()).getHeight() == xMSSNode.getHeight(); hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight() + 1).withTreeIndex(hashTreeAddress.getTreeIndex()).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build()) {
        int i = b / (1 << xMSSNode.getHeight());
        if (i == 1)
          this.authenticationPath.add(xMSSNode); 
        if (i == 3 && xMSSNode.getHeight() < this.treeHeight - this.k)
          ((BDSTreeHash)this.treeHashInstances.get(xMSSNode.getHeight())).setNode(xMSSNode); 
        if (i >= 3 && (i & 0x1) == 1 && xMSSNode.getHeight() >= this.treeHeight - this.k && xMSSNode.getHeight() <= this.treeHeight - 2)
          if (this.retain.get(Integer.valueOf(xMSSNode.getHeight())) == null) {
            LinkedList<XMSSNode> linkedList = new LinkedList();
            linkedList.add(xMSSNode);
            this.retain.put(Integer.valueOf(xMSSNode.getHeight()), linkedList);
          } else {
            ((LinkedList<XMSSNode>)this.retain.get(Integer.valueOf(xMSSNode.getHeight()))).add(xMSSNode);
          }  
        hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(hashTreeAddress.getTreeHeight()).withTreeIndex((hashTreeAddress.getTreeIndex() - 1) / 2).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
        xMSSNode = XMSSNodeUtil.randomizeHash(this.wotsPlus, this.stack.pop(), xMSSNode, hashTreeAddress);
        xMSSNode = new XMSSNode(xMSSNode.getHeight() + 1, xMSSNode.getValue());
      } 
      this.stack.push(xMSSNode);
    } 
    this.root = this.stack.pop();
  }
  
  private void nextAuthenticationPath(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, OTSHashAddress paramOTSHashAddress) {
    if (paramOTSHashAddress == null)
      throw new NullPointerException("otsHashAddress == null"); 
    if (this.used)
      throw new IllegalStateException("index already used"); 
    if (this.index > this.maxIndex - 1)
      throw new IllegalStateException("index out of bounds"); 
    int i = XMSSUtil.calculateTau(this.index, this.treeHeight);
    if ((this.index >> i + 1 & 0x1) == 0 && i < this.treeHeight - 1)
      this.keep.put(Integer.valueOf(i), this.authenticationPath.get(i)); 
    LTreeAddress lTreeAddress = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(paramOTSHashAddress.getLayerAddress()).withTreeAddress(paramOTSHashAddress.getTreeAddress()).build();
    HashTreeAddress hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(paramOTSHashAddress.getLayerAddress()).withTreeAddress(paramOTSHashAddress.getTreeAddress()).build();
    if (i == 0) {
      paramOTSHashAddress = (OTSHashAddress)(new OTSHashAddress.Builder()).withLayerAddress(paramOTSHashAddress.getLayerAddress()).withTreeAddress(paramOTSHashAddress.getTreeAddress()).withOTSAddress(this.index).withChainAddress(paramOTSHashAddress.getChainAddress()).withHashAddress(paramOTSHashAddress.getHashAddress()).withKeyAndMask(paramOTSHashAddress.getKeyAndMask()).build();
      this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(paramArrayOfbyte2, paramOTSHashAddress), paramArrayOfbyte1);
      WOTSPlusPublicKeyParameters wOTSPlusPublicKeyParameters = this.wotsPlus.getPublicKey(paramOTSHashAddress);
      lTreeAddress = (LTreeAddress)(new LTreeAddress.Builder()).withLayerAddress(lTreeAddress.getLayerAddress()).withTreeAddress(lTreeAddress.getTreeAddress()).withLTreeAddress(this.index).withTreeHeight(lTreeAddress.getTreeHeight()).withTreeIndex(lTreeAddress.getTreeIndex()).withKeyAndMask(lTreeAddress.getKeyAndMask()).build();
      XMSSNode xMSSNode = XMSSNodeUtil.lTree(this.wotsPlus, wOTSPlusPublicKeyParameters, lTreeAddress);
      this.authenticationPath.set(0, xMSSNode);
    } else {
      hashTreeAddress = (HashTreeAddress)(new HashTreeAddress.Builder()).withLayerAddress(hashTreeAddress.getLayerAddress()).withTreeAddress(hashTreeAddress.getTreeAddress()).withTreeHeight(i - 1).withTreeIndex(this.index >> i).withKeyAndMask(hashTreeAddress.getKeyAndMask()).build();
      this.wotsPlus.importKeys(this.wotsPlus.getWOTSPlusSecretKey(paramArrayOfbyte2, paramOTSHashAddress), paramArrayOfbyte1);
      XMSSNode xMSSNode = XMSSNodeUtil.randomizeHash(this.wotsPlus, this.authenticationPath.get(i - 1), this.keep.get(Integer.valueOf(i - 1)), hashTreeAddress);
      xMSSNode = new XMSSNode(xMSSNode.getHeight() + 1, xMSSNode.getValue());
      this.authenticationPath.set(i, xMSSNode);
      this.keep.remove(Integer.valueOf(i - 1));
      int j;
      for (j = 0; j < i; j++) {
        if (j < this.treeHeight - this.k) {
          this.authenticationPath.set(j, ((BDSTreeHash)this.treeHashInstances.get(j)).getTailNode());
        } else {
          this.authenticationPath.set(j, ((LinkedList<XMSSNode>)this.retain.get(Integer.valueOf(j))).removeFirst());
        } 
      } 
      j = Math.min(i, this.treeHeight - this.k);
      for (byte b1 = 0; b1 < j; b1++) {
        int k = this.index + 1 + 3 * (1 << b1);
        if (k < 1 << this.treeHeight)
          ((BDSTreeHash)this.treeHashInstances.get(b1)).initialize(k); 
      } 
    } 
    for (byte b = 0; b < this.treeHeight - this.k >> 1; b++) {
      BDSTreeHash bDSTreeHash = getBDSTreeHashInstanceForUpdate();
      if (bDSTreeHash != null)
        bDSTreeHash.update(this.stack, this.wotsPlus, paramArrayOfbyte1, paramArrayOfbyte2, paramOTSHashAddress); 
    } 
    this.index++;
  }
  
  boolean isUsed() {
    return this.used;
  }
  
  void markUsed() {
    this.used = true;
  }
  
  private BDSTreeHash getBDSTreeHashInstanceForUpdate() {
    BDSTreeHash bDSTreeHash = null;
    for (BDSTreeHash bDSTreeHash1 : this.treeHashInstances) {
      if (bDSTreeHash1.isFinished() || !bDSTreeHash1.isInitialized())
        continue; 
      if (bDSTreeHash == null) {
        bDSTreeHash = bDSTreeHash1;
        continue;
      } 
      if (bDSTreeHash1.getHeight() < bDSTreeHash.getHeight()) {
        bDSTreeHash = bDSTreeHash1;
        continue;
      } 
      if (bDSTreeHash1.getHeight() == bDSTreeHash.getHeight() && bDSTreeHash1.getIndexLeaf() < bDSTreeHash.getIndexLeaf())
        bDSTreeHash = bDSTreeHash1; 
    } 
    return bDSTreeHash;
  }
  
  private void validate() {
    if (this.authenticationPath == null)
      throw new IllegalStateException("authenticationPath == null"); 
    if (this.retain == null)
      throw new IllegalStateException("retain == null"); 
    if (this.stack == null)
      throw new IllegalStateException("stack == null"); 
    if (this.treeHashInstances == null)
      throw new IllegalStateException("treeHashInstances == null"); 
    if (this.keep == null)
      throw new IllegalStateException("keep == null"); 
    if (!XMSSUtil.isIndexValid(this.treeHeight, this.index))
      throw new IllegalStateException("index in BDS state out of bounds"); 
  }
  
  protected int getTreeHeight() {
    return this.treeHeight;
  }
  
  protected XMSSNode getRoot() {
    return this.root;
  }
  
  protected List<XMSSNode> getAuthenticationPath() {
    ArrayList<XMSSNode> arrayList = new ArrayList();
    for (XMSSNode xMSSNode : this.authenticationPath)
      arrayList.add(xMSSNode); 
    return arrayList;
  }
  
  protected int getIndex() {
    return this.index;
  }
  
  public int getMaxIndex() {
    return this.maxIndex;
  }
  
  public BDS withWOTSDigest(ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return new BDS(this, paramASN1ObjectIdentifier);
  }
  
  public BDS withMaxIndex(int paramInt, ASN1ObjectIdentifier paramASN1ObjectIdentifier) {
    return new BDS(this, paramInt, paramASN1ObjectIdentifier);
  }
  
  private void readObject(ObjectInputStream paramObjectInputStream) throws IOException, ClassNotFoundException {
    paramObjectInputStream.defaultReadObject();
    if (paramObjectInputStream.available() != 0) {
      this.maxIndex = paramObjectInputStream.readInt();
    } else {
      this.maxIndex = (1 << this.treeHeight) - 1;
    } 
    if (this.maxIndex > (1 << this.treeHeight) - 1 || this.index > this.maxIndex + 1 || paramObjectInputStream.available() != 0)
      throw new IOException("inconsistent BDS data detected"); 
  }
  
  private void writeObject(ObjectOutputStream paramObjectOutputStream) throws IOException {
    paramObjectOutputStream.defaultWriteObject();
    paramObjectOutputStream.writeInt(this.maxIndex);
  }
}
