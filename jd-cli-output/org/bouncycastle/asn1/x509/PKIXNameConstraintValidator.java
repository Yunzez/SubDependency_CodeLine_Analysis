package org.bouncycastle.asn1.x509;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

public class PKIXNameConstraintValidator implements NameConstraintValidator {
  private Set excludedSubtreesDN = new HashSet();
  
  private Set excludedSubtreesDNS = new HashSet();
  
  private Set excludedSubtreesEmail = new HashSet();
  
  private Set excludedSubtreesURI = new HashSet();
  
  private Set excludedSubtreesIP = new HashSet();
  
  private Set excludedSubtreesOtherName = new HashSet();
  
  private Set permittedSubtreesDN;
  
  private Set permittedSubtreesDNS;
  
  private Set permittedSubtreesEmail;
  
  private Set permittedSubtreesURI;
  
  private Set permittedSubtreesIP;
  
  private Set permittedSubtreesOtherName;
  
  public void checkPermitted(GeneralName paramGeneralName) throws NameConstraintValidatorException {
    switch (paramGeneralName.getTagNo()) {
      case 0:
        checkPermittedOtherName(this.permittedSubtreesOtherName, OtherName.getInstance(paramGeneralName.getName()));
        break;
      case 1:
        checkPermittedEmail(this.permittedSubtreesEmail, extractNameAsString(paramGeneralName));
        break;
      case 2:
        checkPermittedDNS(this.permittedSubtreesDNS, extractNameAsString(paramGeneralName));
        break;
      case 4:
        checkPermittedDN(X500Name.getInstance(paramGeneralName.getName()));
        break;
      case 6:
        checkPermittedURI(this.permittedSubtreesURI, extractNameAsString(paramGeneralName));
        break;
      case 7:
        checkPermittedIP(this.permittedSubtreesIP, ASN1OctetString.getInstance(paramGeneralName.getName()).getOctets());
        break;
    } 
  }
  
  public void checkExcluded(GeneralName paramGeneralName) throws NameConstraintValidatorException {
    switch (paramGeneralName.getTagNo()) {
      case 0:
        checkExcludedOtherName(this.excludedSubtreesOtherName, OtherName.getInstance(paramGeneralName.getName()));
        break;
      case 1:
        checkExcludedEmail(this.excludedSubtreesEmail, extractNameAsString(paramGeneralName));
        break;
      case 2:
        checkExcludedDNS(this.excludedSubtreesDNS, extractNameAsString(paramGeneralName));
        break;
      case 4:
        checkExcludedDN(X500Name.getInstance(paramGeneralName.getName()));
        break;
      case 6:
        checkExcludedURI(this.excludedSubtreesURI, extractNameAsString(paramGeneralName));
        break;
      case 7:
        checkExcludedIP(this.excludedSubtreesIP, ASN1OctetString.getInstance(paramGeneralName.getName()).getOctets());
        break;
    } 
  }
  
  public void intersectPermittedSubtree(GeneralSubtree paramGeneralSubtree) {
    intersectPermittedSubtree(new GeneralSubtree[] { paramGeneralSubtree });
  }
  
  public void intersectPermittedSubtree(GeneralSubtree[] paramArrayOfGeneralSubtree) {
    HashMap<Object, Object> hashMap = new HashMap<Object, Object>();
    for (byte b = 0; b != paramArrayOfGeneralSubtree.length; b++) {
      GeneralSubtree generalSubtree = paramArrayOfGeneralSubtree[b];
      Integer integer = Integers.valueOf(generalSubtree.getBase().getTagNo());
      if (hashMap.get(integer) == null)
        hashMap.put(integer, new HashSet()); 
      ((Set<GeneralSubtree>)hashMap.get(integer)).add(generalSubtree);
    } 
    for (Map.Entry<Object, Object> entry : hashMap.entrySet()) {
      int i = ((Integer)entry.getKey()).intValue();
      switch (i) {
        case 0:
          this.permittedSubtreesOtherName = intersectOtherName(this.permittedSubtreesOtherName, (Set)entry.getValue());
          continue;
        case 1:
          this.permittedSubtreesEmail = intersectEmail(this.permittedSubtreesEmail, (Set)entry.getValue());
          continue;
        case 2:
          this.permittedSubtreesDNS = intersectDNS(this.permittedSubtreesDNS, (Set)entry.getValue());
          continue;
        case 4:
          this.permittedSubtreesDN = intersectDN(this.permittedSubtreesDN, (Set)entry.getValue());
          continue;
        case 6:
          this.permittedSubtreesURI = intersectURI(this.permittedSubtreesURI, (Set)entry.getValue());
          continue;
        case 7:
          this.permittedSubtreesIP = intersectIP(this.permittedSubtreesIP, (Set)entry.getValue());
          continue;
      } 
      throw new IllegalStateException("Unknown tag encountered: " + i);
    } 
  }
  
  public void intersectEmptyPermittedSubtree(int paramInt) {
    switch (paramInt) {
      case 0:
        this.permittedSubtreesOtherName = new HashSet();
        return;
      case 1:
        this.permittedSubtreesEmail = new HashSet();
        return;
      case 2:
        this.permittedSubtreesDNS = new HashSet();
        return;
      case 4:
        this.permittedSubtreesDN = new HashSet();
        return;
      case 6:
        this.permittedSubtreesURI = new HashSet();
        return;
      case 7:
        this.permittedSubtreesIP = new HashSet();
        return;
    } 
    throw new IllegalStateException("Unknown tag encountered: " + paramInt);
  }
  
  public void addExcludedSubtree(GeneralSubtree paramGeneralSubtree) {
    GeneralName generalName = paramGeneralSubtree.getBase();
    switch (generalName.getTagNo()) {
      case 0:
        this.excludedSubtreesOtherName = unionOtherName(this.excludedSubtreesOtherName, OtherName.getInstance(generalName.getName()));
        return;
      case 1:
        this.excludedSubtreesEmail = unionEmail(this.excludedSubtreesEmail, extractNameAsString(generalName));
        return;
      case 2:
        this.excludedSubtreesDNS = unionDNS(this.excludedSubtreesDNS, extractNameAsString(generalName));
        return;
      case 4:
        this.excludedSubtreesDN = unionDN(this.excludedSubtreesDN, (ASN1Sequence)generalName.getName().toASN1Primitive());
        return;
      case 6:
        this.excludedSubtreesURI = unionURI(this.excludedSubtreesURI, extractNameAsString(generalName));
        return;
      case 7:
        this.excludedSubtreesIP = unionIP(this.excludedSubtreesIP, ASN1OctetString.getInstance(generalName.getName()).getOctets());
        return;
    } 
    throw new IllegalStateException("Unknown tag encountered: " + generalName.getTagNo());
  }
  
  public int hashCode() {
    return hashCollection(this.excludedSubtreesDN) + hashCollection(this.excludedSubtreesDNS) + hashCollection(this.excludedSubtreesEmail) + hashCollection(this.excludedSubtreesIP) + hashCollection(this.excludedSubtreesURI) + hashCollection(this.excludedSubtreesOtherName) + hashCollection(this.permittedSubtreesDN) + hashCollection(this.permittedSubtreesDNS) + hashCollection(this.permittedSubtreesEmail) + hashCollection(this.permittedSubtreesIP) + hashCollection(this.permittedSubtreesURI) + hashCollection(this.permittedSubtreesOtherName);
  }
  
  public boolean equals(Object paramObject) {
    if (!(paramObject instanceof PKIXNameConstraintValidator))
      return false; 
    PKIXNameConstraintValidator pKIXNameConstraintValidator = (PKIXNameConstraintValidator)paramObject;
    return (collectionsAreEqual(pKIXNameConstraintValidator.excludedSubtreesDN, this.excludedSubtreesDN) && collectionsAreEqual(pKIXNameConstraintValidator.excludedSubtreesDNS, this.excludedSubtreesDNS) && collectionsAreEqual(pKIXNameConstraintValidator.excludedSubtreesEmail, this.excludedSubtreesEmail) && collectionsAreEqual(pKIXNameConstraintValidator.excludedSubtreesIP, this.excludedSubtreesIP) && collectionsAreEqual(pKIXNameConstraintValidator.excludedSubtreesURI, this.excludedSubtreesURI) && collectionsAreEqual(pKIXNameConstraintValidator.excludedSubtreesOtherName, this.excludedSubtreesOtherName) && collectionsAreEqual(pKIXNameConstraintValidator.permittedSubtreesDN, this.permittedSubtreesDN) && collectionsAreEqual(pKIXNameConstraintValidator.permittedSubtreesDNS, this.permittedSubtreesDNS) && collectionsAreEqual(pKIXNameConstraintValidator.permittedSubtreesEmail, this.permittedSubtreesEmail) && collectionsAreEqual(pKIXNameConstraintValidator.permittedSubtreesIP, this.permittedSubtreesIP) && collectionsAreEqual(pKIXNameConstraintValidator.permittedSubtreesURI, this.permittedSubtreesURI) && collectionsAreEqual(pKIXNameConstraintValidator.permittedSubtreesOtherName, this.permittedSubtreesOtherName));
  }
  
  public void checkPermittedDN(X500Name paramX500Name) throws NameConstraintValidatorException {
    checkPermittedDN(this.permittedSubtreesDN, ASN1Sequence.getInstance(paramX500Name.toASN1Primitive()));
  }
  
  public void checkExcludedDN(X500Name paramX500Name) throws NameConstraintValidatorException {
    checkExcludedDN(this.excludedSubtreesDN, ASN1Sequence.getInstance(paramX500Name));
  }
  
  private static boolean withinDNSubtree(ASN1Sequence paramASN1Sequence1, ASN1Sequence paramASN1Sequence2) {
    if (paramASN1Sequence2.size() < 1)
      return false; 
    if (paramASN1Sequence2.size() > paramASN1Sequence1.size())
      return false; 
    byte b1 = 0;
    RDN rDN = RDN.getInstance(paramASN1Sequence2.getObjectAt(0));
    byte b2;
    for (b2 = 0; b2 < paramASN1Sequence1.size(); b2++) {
      b1 = b2;
      RDN rDN1 = RDN.getInstance(paramASN1Sequence1.getObjectAt(b2));
      if (IETFUtils.rDNAreEqual(rDN, rDN1))
        break; 
    } 
    if (paramASN1Sequence2.size() > paramASN1Sequence1.size() - b1)
      return false; 
    for (b2 = 0; b2 < paramASN1Sequence2.size(); b2++) {
      RDN rDN1 = RDN.getInstance(paramASN1Sequence2.getObjectAt(b2));
      RDN rDN2 = RDN.getInstance(paramASN1Sequence1.getObjectAt(b1 + b2));
      if (rDN1.size() == rDN2.size()) {
        if (!rDN1.getFirst().getType().equals(rDN2.getFirst().getType()))
          return false; 
        if (rDN1.size() == 1 && rDN1.getFirst().getType().equals(RFC4519Style.serialNumber)) {
          if (!rDN2.getFirst().getValue().toString().startsWith(rDN1.getFirst().getValue().toString()))
            return false; 
        } else if (!IETFUtils.rDNAreEqual(rDN1, rDN2)) {
          return false;
        } 
      } else {
        return false;
      } 
    } 
    return true;
  }
  
  private void checkPermittedDN(Set paramSet, ASN1Sequence paramASN1Sequence) throws NameConstraintValidatorException {
    if (paramSet == null)
      return; 
    if (paramSet.isEmpty() && paramASN1Sequence.size() == 0)
      return; 
    for (ASN1Sequence aSN1Sequence : paramSet) {
      if (withinDNSubtree(paramASN1Sequence, aSN1Sequence))
        return; 
    } 
    throw new NameConstraintValidatorException("Subject distinguished name is not from a permitted subtree");
  }
  
  private void checkExcludedDN(Set paramSet, ASN1Sequence paramASN1Sequence) throws NameConstraintValidatorException {
    if (paramSet.isEmpty())
      return; 
    for (ASN1Sequence aSN1Sequence : paramSet) {
      if (withinDNSubtree(paramASN1Sequence, aSN1Sequence))
        throw new NameConstraintValidatorException("Subject distinguished name is from an excluded subtree"); 
    } 
  }
  
  private Set intersectDN(Set paramSet1, Set paramSet2) {
    HashSet<ASN1Sequence> hashSet = new HashSet();
    Iterator<GeneralSubtree> iterator = paramSet2.iterator();
    while (iterator.hasNext()) {
      ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(((GeneralSubtree)iterator.next()).getBase().getName().toASN1Primitive());
      if (paramSet1 == null) {
        if (aSN1Sequence != null)
          hashSet.add(aSN1Sequence); 
        continue;
      } 
      for (ASN1Sequence aSN1Sequence1 : paramSet1) {
        if (withinDNSubtree(aSN1Sequence, aSN1Sequence1)) {
          hashSet.add(aSN1Sequence);
          continue;
        } 
        if (withinDNSubtree(aSN1Sequence1, aSN1Sequence))
          hashSet.add(aSN1Sequence1); 
      } 
    } 
    return hashSet;
  }
  
  private Set unionDN(Set<ASN1Sequence> paramSet, ASN1Sequence paramASN1Sequence) {
    if (paramSet.isEmpty()) {
      if (paramASN1Sequence == null)
        return paramSet; 
      paramSet.add(paramASN1Sequence);
      return paramSet;
    } 
    HashSet<ASN1Sequence> hashSet = new HashSet();
    Iterator<ASN1Sequence> iterator = paramSet.iterator();
    while (iterator.hasNext()) {
      ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(iterator.next());
      if (withinDNSubtree(paramASN1Sequence, aSN1Sequence)) {
        hashSet.add(aSN1Sequence);
        continue;
      } 
      if (withinDNSubtree(aSN1Sequence, paramASN1Sequence)) {
        hashSet.add(paramASN1Sequence);
        continue;
      } 
      hashSet.add(aSN1Sequence);
      hashSet.add(paramASN1Sequence);
    } 
    return hashSet;
  }
  
  private Set intersectOtherName(Set paramSet1, Set paramSet2) {
    HashSet<OtherName> hashSet = new HashSet();
    Iterator<GeneralSubtree> iterator = paramSet2.iterator();
    while (iterator.hasNext()) {
      OtherName otherName = OtherName.getInstance(((GeneralSubtree)iterator.next()).getBase().getName());
      if (paramSet1 == null) {
        if (otherName != null)
          hashSet.add(otherName); 
        continue;
      } 
      Iterator iterator1 = paramSet1.iterator();
      while (iterator1.hasNext()) {
        OtherName otherName1 = OtherName.getInstance(iterator1.next());
        intersectOtherName(otherName, otherName1, hashSet);
      } 
    } 
    return hashSet;
  }
  
  private void intersectOtherName(OtherName paramOtherName1, OtherName paramOtherName2, Set<OtherName> paramSet) {
    if (paramOtherName1.equals(paramOtherName2))
      paramSet.add(paramOtherName1); 
  }
  
  private Set unionOtherName(Set<?> paramSet, OtherName paramOtherName) {
    HashSet<OtherName> hashSet = (paramSet != null) ? new HashSet(paramSet) : new HashSet();
    hashSet.add(paramOtherName);
    return hashSet;
  }
  
  private Set intersectEmail(Set paramSet1, Set paramSet2) {
    HashSet<String> hashSet = new HashSet();
    Iterator<GeneralSubtree> iterator = paramSet2.iterator();
    while (iterator.hasNext()) {
      String str = extractNameAsString(((GeneralSubtree)iterator.next()).getBase());
      if (paramSet1 == null) {
        if (str != null)
          hashSet.add(str); 
        continue;
      } 
      for (String str1 : paramSet1)
        intersectEmail(str, str1, hashSet); 
    } 
    return hashSet;
  }
  
  private Set unionEmail(Set<String> paramSet, String paramString) {
    if (paramSet.isEmpty()) {
      if (paramString == null)
        return paramSet; 
      paramSet.add(paramString);
      return paramSet;
    } 
    HashSet hashSet = new HashSet();
    for (String str : paramSet)
      unionEmail(str, paramString, hashSet); 
    return hashSet;
  }
  
  private Set intersectIP(Set paramSet1, Set paramSet2) {
    HashSet<byte[]> hashSet = new HashSet();
    Iterator<GeneralSubtree> iterator = paramSet2.iterator();
    while (iterator.hasNext()) {
      byte[] arrayOfByte = ASN1OctetString.getInstance(((GeneralSubtree)iterator.next()).getBase().getName()).getOctets();
      if (paramSet1 == null) {
        if (arrayOfByte != null)
          hashSet.add(arrayOfByte); 
        continue;
      } 
      for (byte[] arrayOfByte1 : paramSet1)
        hashSet.addAll(intersectIPRange(arrayOfByte1, arrayOfByte)); 
    } 
    return hashSet;
  }
  
  private Set unionIP(Set<byte[]> paramSet, byte[] paramArrayOfbyte) {
    if (paramSet.isEmpty()) {
      if (paramArrayOfbyte == null)
        return paramSet; 
      paramSet.add(paramArrayOfbyte);
      return paramSet;
    } 
    HashSet hashSet = new HashSet();
    for (byte[] arrayOfByte : paramSet)
      hashSet.addAll(unionIPRange(arrayOfByte, paramArrayOfbyte)); 
    return hashSet;
  }
  
  private Set unionIPRange(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    HashSet<byte[]> hashSet = new HashSet();
    if (Arrays.areEqual(paramArrayOfbyte1, paramArrayOfbyte2)) {
      hashSet.add(paramArrayOfbyte1);
    } else {
      hashSet.add(paramArrayOfbyte1);
      hashSet.add(paramArrayOfbyte2);
    } 
    return hashSet;
  }
  
  private Set intersectIPRange(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    if (paramArrayOfbyte1.length != paramArrayOfbyte2.length)
      return Collections.EMPTY_SET; 
    byte[][] arrayOfByte1 = extractIPsAndSubnetMasks(paramArrayOfbyte1, paramArrayOfbyte2);
    byte[] arrayOfByte2 = arrayOfByte1[0];
    byte[] arrayOfByte3 = arrayOfByte1[1];
    byte[] arrayOfByte4 = arrayOfByte1[2];
    byte[] arrayOfByte5 = arrayOfByte1[3];
    byte[][] arrayOfByte6 = minMaxIPs(arrayOfByte2, arrayOfByte3, arrayOfByte4, arrayOfByte5);
    byte[] arrayOfByte8 = min(arrayOfByte6[1], arrayOfByte6[3]);
    byte[] arrayOfByte7 = max(arrayOfByte6[0], arrayOfByte6[2]);
    if (compareTo(arrayOfByte7, arrayOfByte8) == 1)
      return Collections.EMPTY_SET; 
    byte[] arrayOfByte9 = or(arrayOfByte6[0], arrayOfByte6[2]);
    byte[] arrayOfByte10 = or(arrayOfByte3, arrayOfByte5);
    return Collections.singleton(ipWithSubnetMask(arrayOfByte9, arrayOfByte10));
  }
  
  private byte[] ipWithSubnetMask(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    int i = paramArrayOfbyte1.length;
    byte[] arrayOfByte = new byte[i * 2];
    System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte, 0, i);
    System.arraycopy(paramArrayOfbyte2, 0, arrayOfByte, i, i);
    return arrayOfByte;
  }
  
  private byte[][] extractIPsAndSubnetMasks(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    int i = paramArrayOfbyte1.length / 2;
    byte[] arrayOfByte1 = new byte[i];
    byte[] arrayOfByte2 = new byte[i];
    System.arraycopy(paramArrayOfbyte1, 0, arrayOfByte1, 0, i);
    System.arraycopy(paramArrayOfbyte1, i, arrayOfByte2, 0, i);
    byte[] arrayOfByte3 = new byte[i];
    byte[] arrayOfByte4 = new byte[i];
    System.arraycopy(paramArrayOfbyte2, 0, arrayOfByte3, 0, i);
    System.arraycopy(paramArrayOfbyte2, i, arrayOfByte4, 0, i);
    return new byte[][] { arrayOfByte1, arrayOfByte2, arrayOfByte3, arrayOfByte4 };
  }
  
  private byte[][] minMaxIPs(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, byte[] paramArrayOfbyte3, byte[] paramArrayOfbyte4) {
    int i = paramArrayOfbyte1.length;
    byte[] arrayOfByte1 = new byte[i];
    byte[] arrayOfByte2 = new byte[i];
    byte[] arrayOfByte3 = new byte[i];
    byte[] arrayOfByte4 = new byte[i];
    for (byte b = 0; b < i; b++) {
      arrayOfByte1[b] = (byte)(paramArrayOfbyte1[b] & paramArrayOfbyte2[b]);
      arrayOfByte2[b] = (byte)(paramArrayOfbyte1[b] & paramArrayOfbyte2[b] | paramArrayOfbyte2[b] ^ 0xFFFFFFFF);
      arrayOfByte3[b] = (byte)(paramArrayOfbyte3[b] & paramArrayOfbyte4[b]);
      arrayOfByte4[b] = (byte)(paramArrayOfbyte3[b] & paramArrayOfbyte4[b] | paramArrayOfbyte4[b] ^ 0xFFFFFFFF);
    } 
    return new byte[][] { arrayOfByte1, arrayOfByte2, arrayOfByte3, arrayOfByte4 };
  }
  
  private void checkPermittedEmail(Set paramSet, String paramString) throws NameConstraintValidatorException {
    if (paramSet == null)
      return; 
    for (String str : paramSet) {
      if (emailIsConstrained(paramString, str))
        return; 
    } 
    if (paramString.length() == 0 && paramSet.size() == 0)
      return; 
    throw new NameConstraintValidatorException("Subject email address is not from a permitted subtree.");
  }
  
  private void checkPermittedOtherName(Set paramSet, OtherName paramOtherName) throws NameConstraintValidatorException {
    if (paramSet == null)
      return; 
    Iterator iterator = paramSet.iterator();
    while (iterator.hasNext()) {
      OtherName otherName = OtherName.getInstance(iterator.next());
      if (otherNameIsConstrained(paramOtherName, otherName))
        return; 
    } 
    throw new NameConstraintValidatorException("Subject OtherName is not from a permitted subtree.");
  }
  
  private void checkExcludedOtherName(Set paramSet, OtherName paramOtherName) throws NameConstraintValidatorException {
    if (paramSet.isEmpty())
      return; 
    Iterator iterator = paramSet.iterator();
    while (iterator.hasNext()) {
      OtherName otherName = OtherName.getInstance(iterator.next());
      if (otherNameIsConstrained(paramOtherName, otherName))
        throw new NameConstraintValidatorException("OtherName is from an excluded subtree."); 
    } 
  }
  
  private void checkExcludedEmail(Set paramSet, String paramString) throws NameConstraintValidatorException {
    if (paramSet.isEmpty())
      return; 
    for (String str : paramSet) {
      if (emailIsConstrained(paramString, str))
        throw new NameConstraintValidatorException("Email address is from an excluded subtree."); 
    } 
  }
  
  private void checkPermittedIP(Set paramSet, byte[] paramArrayOfbyte) throws NameConstraintValidatorException {
    if (paramSet == null)
      return; 
    for (byte[] arrayOfByte : paramSet) {
      if (isIPConstrained(paramArrayOfbyte, arrayOfByte))
        return; 
    } 
    if (paramArrayOfbyte.length == 0 && paramSet.size() == 0)
      return; 
    throw new NameConstraintValidatorException("IP is not from a permitted subtree.");
  }
  
  private void checkExcludedIP(Set paramSet, byte[] paramArrayOfbyte) throws NameConstraintValidatorException {
    if (paramSet.isEmpty())
      return; 
    for (byte[] arrayOfByte : paramSet) {
      if (isIPConstrained(paramArrayOfbyte, arrayOfByte))
        throw new NameConstraintValidatorException("IP is from an excluded subtree."); 
    } 
  }
  
  private boolean isIPConstrained(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    int i = paramArrayOfbyte1.length;
    if (i != paramArrayOfbyte2.length / 2)
      return false; 
    byte[] arrayOfByte1 = new byte[i];
    System.arraycopy(paramArrayOfbyte2, i, arrayOfByte1, 0, i);
    byte[] arrayOfByte2 = new byte[i];
    byte[] arrayOfByte3 = new byte[i];
    for (byte b = 0; b < i; b++) {
      arrayOfByte2[b] = (byte)(paramArrayOfbyte2[b] & arrayOfByte1[b]);
      arrayOfByte3[b] = (byte)(paramArrayOfbyte1[b] & arrayOfByte1[b]);
    } 
    return Arrays.areEqual(arrayOfByte2, arrayOfByte3);
  }
  
  private boolean otherNameIsConstrained(OtherName paramOtherName1, OtherName paramOtherName2) {
    return paramOtherName2.equals(paramOtherName1);
  }
  
  private boolean emailIsConstrained(String paramString1, String paramString2) {
    String str = paramString1.substring(paramString1.indexOf('@') + 1);
    if (paramString2.indexOf('@') != -1) {
      if (paramString1.equalsIgnoreCase(paramString2))
        return true; 
      if (str.equalsIgnoreCase(paramString2.substring(1)))
        return true; 
    } else if (paramString2.charAt(0) != '.') {
      if (str.equalsIgnoreCase(paramString2))
        return true; 
    } else if (withinDomain(str, paramString2)) {
      return true;
    } 
    return false;
  }
  
  private boolean withinDomain(String paramString1, String paramString2) {
    String str = paramString2;
    if (str.startsWith("."))
      str = str.substring(1); 
    String[] arrayOfString1 = Strings.split(str, '.');
    String[] arrayOfString2 = Strings.split(paramString1, '.');
    if (arrayOfString2.length <= arrayOfString1.length)
      return false; 
    int i = arrayOfString2.length - arrayOfString1.length;
    for (byte b = -1; b < arrayOfString1.length; b++) {
      if (b == -1) {
        if (arrayOfString2[b + i].equals(""))
          return false; 
      } else if (!arrayOfString1[b].equalsIgnoreCase(arrayOfString2[b + i])) {
        return false;
      } 
    } 
    return true;
  }
  
  private void checkPermittedDNS(Set paramSet, String paramString) throws NameConstraintValidatorException {
    if (paramSet == null)
      return; 
    for (String str : paramSet) {
      if (withinDomain(paramString, str) || paramString.equalsIgnoreCase(str))
        return; 
    } 
    if (paramString.length() == 0 && paramSet.size() == 0)
      return; 
    throw new NameConstraintValidatorException("DNS is not from a permitted subtree.");
  }
  
  private void checkExcludedDNS(Set paramSet, String paramString) throws NameConstraintValidatorException {
    if (paramSet.isEmpty())
      return; 
    for (String str : paramSet) {
      if (withinDomain(paramString, str) || paramString.equalsIgnoreCase(str))
        throw new NameConstraintValidatorException("DNS is from an excluded subtree."); 
    } 
  }
  
  private void unionEmail(String paramString1, String paramString2, Set<String> paramSet) {
    if (paramString1.indexOf('@') != -1) {
      String str = paramString1.substring(paramString1.indexOf('@') + 1);
      if (paramString2.indexOf('@') != -1) {
        if (paramString1.equalsIgnoreCase(paramString2)) {
          paramSet.add(paramString1);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(str, paramString2)) {
          paramSet.add(paramString2);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (str.equalsIgnoreCase(paramString2)) {
        paramSet.add(paramString2);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString1.startsWith(".")) {
      if (paramString2.indexOf('@') != -1) {
        String str = paramString2.substring(paramString1.indexOf('@') + 1);
        if (withinDomain(str, paramString1)) {
          paramSet.add(paramString1);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(paramString1, paramString2) || paramString1.equalsIgnoreCase(paramString2)) {
          paramSet.add(paramString2);
        } else if (withinDomain(paramString2, paramString1)) {
          paramSet.add(paramString1);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (withinDomain(paramString2, paramString1)) {
        paramSet.add(paramString1);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString2.indexOf('@') != -1) {
      String str = paramString2.substring(paramString1.indexOf('@') + 1);
      if (str.equalsIgnoreCase(paramString1)) {
        paramSet.add(paramString1);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString2.startsWith(".")) {
      if (withinDomain(paramString1, paramString2)) {
        paramSet.add(paramString2);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString1.equalsIgnoreCase(paramString2)) {
      paramSet.add(paramString1);
    } else {
      paramSet.add(paramString1);
      paramSet.add(paramString2);
    } 
  }
  
  private void unionURI(String paramString1, String paramString2, Set<String> paramSet) {
    if (paramString1.indexOf('@') != -1) {
      String str = paramString1.substring(paramString1.indexOf('@') + 1);
      if (paramString2.indexOf('@') != -1) {
        if (paramString1.equalsIgnoreCase(paramString2)) {
          paramSet.add(paramString1);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(str, paramString2)) {
          paramSet.add(paramString2);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (str.equalsIgnoreCase(paramString2)) {
        paramSet.add(paramString2);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString1.startsWith(".")) {
      if (paramString2.indexOf('@') != -1) {
        String str = paramString2.substring(paramString1.indexOf('@') + 1);
        if (withinDomain(str, paramString1)) {
          paramSet.add(paramString1);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(paramString1, paramString2) || paramString1.equalsIgnoreCase(paramString2)) {
          paramSet.add(paramString2);
        } else if (withinDomain(paramString2, paramString1)) {
          paramSet.add(paramString1);
        } else {
          paramSet.add(paramString1);
          paramSet.add(paramString2);
        } 
      } else if (withinDomain(paramString2, paramString1)) {
        paramSet.add(paramString1);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString2.indexOf('@') != -1) {
      String str = paramString2.substring(paramString1.indexOf('@') + 1);
      if (str.equalsIgnoreCase(paramString1)) {
        paramSet.add(paramString1);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString2.startsWith(".")) {
      if (withinDomain(paramString1, paramString2)) {
        paramSet.add(paramString2);
      } else {
        paramSet.add(paramString1);
        paramSet.add(paramString2);
      } 
    } else if (paramString1.equalsIgnoreCase(paramString2)) {
      paramSet.add(paramString1);
    } else {
      paramSet.add(paramString1);
      paramSet.add(paramString2);
    } 
  }
  
  private Set intersectDNS(Set paramSet1, Set paramSet2) {
    HashSet<String> hashSet = new HashSet();
    Iterator<GeneralSubtree> iterator = paramSet2.iterator();
    while (iterator.hasNext()) {
      String str = extractNameAsString(((GeneralSubtree)iterator.next()).getBase());
      if (paramSet1 == null) {
        if (str != null)
          hashSet.add(str); 
        continue;
      } 
      for (String str1 : paramSet1) {
        if (withinDomain(str1, str)) {
          hashSet.add(str1);
          continue;
        } 
        if (withinDomain(str, str1))
          hashSet.add(str); 
      } 
    } 
    return hashSet;
  }
  
  private Set unionDNS(Set<String> paramSet, String paramString) {
    if (paramSet.isEmpty()) {
      if (paramString == null)
        return paramSet; 
      paramSet.add(paramString);
      return paramSet;
    } 
    HashSet<String> hashSet = new HashSet();
    for (String str : paramSet) {
      if (withinDomain(str, paramString)) {
        hashSet.add(paramString);
        continue;
      } 
      if (withinDomain(paramString, str)) {
        hashSet.add(str);
        continue;
      } 
      hashSet.add(str);
      hashSet.add(paramString);
    } 
    return hashSet;
  }
  
  private void intersectEmail(String paramString1, String paramString2, Set<String> paramSet) {
    if (paramString1.indexOf('@') != -1) {
      String str = paramString1.substring(paramString1.indexOf('@') + 1);
      if (paramString2.indexOf('@') != -1) {
        if (paramString1.equalsIgnoreCase(paramString2))
          paramSet.add(paramString1); 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(str, paramString2))
          paramSet.add(paramString1); 
      } else if (str.equalsIgnoreCase(paramString2)) {
        paramSet.add(paramString1);
      } 
    } else if (paramString1.startsWith(".")) {
      if (paramString2.indexOf('@') != -1) {
        String str = paramString2.substring(paramString1.indexOf('@') + 1);
        if (withinDomain(str, paramString1))
          paramSet.add(paramString2); 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(paramString1, paramString2) || paramString1.equalsIgnoreCase(paramString2)) {
          paramSet.add(paramString1);
        } else if (withinDomain(paramString2, paramString1)) {
          paramSet.add(paramString2);
        } 
      } else if (withinDomain(paramString2, paramString1)) {
        paramSet.add(paramString2);
      } 
    } else if (paramString2.indexOf('@') != -1) {
      String str = paramString2.substring(paramString2.indexOf('@') + 1);
      if (str.equalsIgnoreCase(paramString1))
        paramSet.add(paramString2); 
    } else if (paramString2.startsWith(".")) {
      if (withinDomain(paramString1, paramString2))
        paramSet.add(paramString1); 
    } else if (paramString1.equalsIgnoreCase(paramString2)) {
      paramSet.add(paramString1);
    } 
  }
  
  private void checkExcludedURI(Set paramSet, String paramString) throws NameConstraintValidatorException {
    if (paramSet.isEmpty())
      return; 
    for (String str : paramSet) {
      if (isUriConstrained(paramString, str))
        throw new NameConstraintValidatorException("URI is from an excluded subtree."); 
    } 
  }
  
  private Set intersectURI(Set paramSet1, Set paramSet2) {
    HashSet<String> hashSet = new HashSet();
    Iterator<GeneralSubtree> iterator = paramSet2.iterator();
    while (iterator.hasNext()) {
      String str = extractNameAsString(((GeneralSubtree)iterator.next()).getBase());
      if (paramSet1 == null) {
        if (str != null)
          hashSet.add(str); 
        continue;
      } 
      for (String str1 : paramSet1)
        intersectURI(str1, str, hashSet); 
    } 
    return hashSet;
  }
  
  private Set unionURI(Set<String> paramSet, String paramString) {
    if (paramSet.isEmpty()) {
      if (paramString == null)
        return paramSet; 
      paramSet.add(paramString);
      return paramSet;
    } 
    HashSet hashSet = new HashSet();
    for (String str : paramSet)
      unionURI(str, paramString, hashSet); 
    return hashSet;
  }
  
  private void intersectURI(String paramString1, String paramString2, Set<String> paramSet) {
    if (paramString1.indexOf('@') != -1) {
      String str = paramString1.substring(paramString1.indexOf('@') + 1);
      if (paramString2.indexOf('@') != -1) {
        if (paramString1.equalsIgnoreCase(paramString2))
          paramSet.add(paramString1); 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(str, paramString2))
          paramSet.add(paramString1); 
      } else if (str.equalsIgnoreCase(paramString2)) {
        paramSet.add(paramString1);
      } 
    } else if (paramString1.startsWith(".")) {
      if (paramString2.indexOf('@') != -1) {
        String str = paramString2.substring(paramString1.indexOf('@') + 1);
        if (withinDomain(str, paramString1))
          paramSet.add(paramString2); 
      } else if (paramString2.startsWith(".")) {
        if (withinDomain(paramString1, paramString2) || paramString1.equalsIgnoreCase(paramString2)) {
          paramSet.add(paramString1);
        } else if (withinDomain(paramString2, paramString1)) {
          paramSet.add(paramString2);
        } 
      } else if (withinDomain(paramString2, paramString1)) {
        paramSet.add(paramString2);
      } 
    } else if (paramString2.indexOf('@') != -1) {
      String str = paramString2.substring(paramString2.indexOf('@') + 1);
      if (str.equalsIgnoreCase(paramString1))
        paramSet.add(paramString2); 
    } else if (paramString2.startsWith(".")) {
      if (withinDomain(paramString1, paramString2))
        paramSet.add(paramString1); 
    } else if (paramString1.equalsIgnoreCase(paramString2)) {
      paramSet.add(paramString1);
    } 
  }
  
  private void checkPermittedURI(Set paramSet, String paramString) throws NameConstraintValidatorException {
    if (paramSet == null)
      return; 
    for (String str : paramSet) {
      if (isUriConstrained(paramString, str))
        return; 
    } 
    if (paramString.length() == 0 && paramSet.size() == 0)
      return; 
    throw new NameConstraintValidatorException("URI is not from a permitted subtree.");
  }
  
  private boolean isUriConstrained(String paramString1, String paramString2) {
    String str = extractHostFromURL(paramString1);
    if (!paramString2.startsWith(".")) {
      if (str.equalsIgnoreCase(paramString2))
        return true; 
    } else if (withinDomain(str, paramString2)) {
      return true;
    } 
    return false;
  }
  
  private static String extractHostFromURL(String paramString) {
    String str = paramString.substring(paramString.indexOf(':') + 1);
    if (str.indexOf("//") != -1)
      str = str.substring(str.indexOf("//") + 2); 
    if (str.lastIndexOf(':') != -1)
      str = str.substring(0, str.lastIndexOf(':')); 
    str = str.substring(str.indexOf(':') + 1);
    str = str.substring(str.indexOf('@') + 1);
    if (str.indexOf('/') != -1)
      str = str.substring(0, str.indexOf('/')); 
    return str;
  }
  
  private String extractNameAsString(GeneralName paramGeneralName) {
    return ASN1IA5String.getInstance(paramGeneralName.getName()).getString();
  }
  
  private static byte[] max(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    for (byte b = 0; b < paramArrayOfbyte1.length; b++) {
      if ((paramArrayOfbyte1[b] & 0xFFFF) > (paramArrayOfbyte2[b] & 0xFFFF))
        return paramArrayOfbyte1; 
    } 
    return paramArrayOfbyte2;
  }
  
  private static byte[] min(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    for (byte b = 0; b < paramArrayOfbyte1.length; b++) {
      if ((paramArrayOfbyte1[b] & 0xFFFF) < (paramArrayOfbyte2[b] & 0xFFFF))
        return paramArrayOfbyte1; 
    } 
    return paramArrayOfbyte2;
  }
  
  private static int compareTo(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    return Arrays.areEqual(paramArrayOfbyte1, paramArrayOfbyte2) ? 0 : (Arrays.areEqual(max(paramArrayOfbyte1, paramArrayOfbyte2), paramArrayOfbyte1) ? 1 : -1);
  }
  
  private static byte[] or(byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2) {
    byte[] arrayOfByte = new byte[paramArrayOfbyte1.length];
    for (byte b = 0; b < paramArrayOfbyte1.length; b++)
      arrayOfByte[b] = (byte)(paramArrayOfbyte1[b] | paramArrayOfbyte2[b]); 
    return arrayOfByte;
  }
  
  private int hashCollection(Collection paramCollection) {
    if (paramCollection == null)
      return 0; 
    int i = 0;
    for (byte[] arrayOfByte : paramCollection) {
      if (arrayOfByte instanceof byte[]) {
        i += Arrays.hashCode(arrayOfByte);
        continue;
      } 
      i += arrayOfByte.hashCode();
    } 
    return i;
  }
  
  private boolean collectionsAreEqual(Collection paramCollection1, Collection paramCollection2) {
    if (paramCollection1 == paramCollection2)
      return true; 
    if (paramCollection1 == null || paramCollection2 == null)
      return false; 
    if (paramCollection1.size() != paramCollection2.size())
      return false; 
    for (Object object : paramCollection1) {
      Iterator<Object> iterator = paramCollection2.iterator();
      boolean bool = false;
      while (iterator.hasNext()) {
        Object object1 = iterator.next();
        if (equals(object, object1)) {
          bool = true;
          break;
        } 
      } 
      if (!bool)
        return false; 
    } 
    return true;
  }
  
  private boolean equals(Object paramObject1, Object paramObject2) {
    return (paramObject1 == paramObject2) ? true : ((paramObject1 == null || paramObject2 == null) ? false : ((paramObject1 instanceof byte[] && paramObject2 instanceof byte[]) ? Arrays.areEqual((byte[])paramObject1, (byte[])paramObject2) : paramObject1.equals(paramObject2)));
  }
  
  private String stringifyIP(byte[] paramArrayOfbyte) {
    StringBuilder stringBuilder = new StringBuilder();
    byte b;
    for (b = 0; b < paramArrayOfbyte.length / 2; b++) {
      if (stringBuilder.length() > 0)
        stringBuilder.append("."); 
      stringBuilder.append(Integer.toString(paramArrayOfbyte[b] & 0xFF));
    } 
    stringBuilder.append("/");
    b = 1;
    for (int i = paramArrayOfbyte.length / 2; i < paramArrayOfbyte.length; i++) {
      if (b != 0) {
        b = 0;
      } else {
        stringBuilder.append(".");
      } 
      stringBuilder.append(Integer.toString(paramArrayOfbyte[i] & 0xFF));
    } 
    return stringBuilder.toString();
  }
  
  private String stringifyIPCollection(Set paramSet) {
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("[");
    Iterator<byte[]> iterator = paramSet.iterator();
    while (iterator.hasNext()) {
      if (stringBuilder.length() > 1)
        stringBuilder.append(","); 
      stringBuilder.append(stringifyIP(iterator.next()));
    } 
    stringBuilder.append("]");
    return stringBuilder.toString();
  }
  
  private String stringifyOtherNameCollection(Set paramSet) {
    StringBuilder stringBuilder = new StringBuilder();
    stringBuilder.append("[");
    Iterator iterator = paramSet.iterator();
    while (iterator.hasNext()) {
      if (stringBuilder.length() > 1)
        stringBuilder.append(","); 
      OtherName otherName = OtherName.getInstance(iterator.next());
      stringBuilder.append(otherName.getTypeID().getId());
      stringBuilder.append(":");
      try {
        stringBuilder.append(Hex.toHexString(otherName.getValue().toASN1Primitive().getEncoded()));
      } catch (IOException iOException) {
        stringBuilder.append(iOException.toString());
      } 
    } 
    stringBuilder.append("]");
    return stringBuilder.toString();
  }
  
  private final void addLine(StringBuilder paramStringBuilder, String paramString) {
    paramStringBuilder.append(paramString).append(Strings.lineSeparator());
  }
  
  public String toString() {
    StringBuilder stringBuilder = new StringBuilder();
    addLine(stringBuilder, "permitted:");
    if (this.permittedSubtreesDN != null) {
      addLine(stringBuilder, "DN:");
      addLine(stringBuilder, this.permittedSubtreesDN.toString());
    } 
    if (this.permittedSubtreesDNS != null) {
      addLine(stringBuilder, "DNS:");
      addLine(stringBuilder, this.permittedSubtreesDNS.toString());
    } 
    if (this.permittedSubtreesEmail != null) {
      addLine(stringBuilder, "Email:");
      addLine(stringBuilder, this.permittedSubtreesEmail.toString());
    } 
    if (this.permittedSubtreesURI != null) {
      addLine(stringBuilder, "URI:");
      addLine(stringBuilder, this.permittedSubtreesURI.toString());
    } 
    if (this.permittedSubtreesIP != null) {
      addLine(stringBuilder, "IP:");
      addLine(stringBuilder, stringifyIPCollection(this.permittedSubtreesIP));
    } 
    if (this.permittedSubtreesOtherName != null) {
      addLine(stringBuilder, "OtherName:");
      addLine(stringBuilder, stringifyOtherNameCollection(this.permittedSubtreesOtherName));
    } 
    addLine(stringBuilder, "excluded:");
    if (!this.excludedSubtreesDN.isEmpty()) {
      addLine(stringBuilder, "DN:");
      addLine(stringBuilder, this.excludedSubtreesDN.toString());
    } 
    if (!this.excludedSubtreesDNS.isEmpty()) {
      addLine(stringBuilder, "DNS:");
      addLine(stringBuilder, this.excludedSubtreesDNS.toString());
    } 
    if (!this.excludedSubtreesEmail.isEmpty()) {
      addLine(stringBuilder, "Email:");
      addLine(stringBuilder, this.excludedSubtreesEmail.toString());
    } 
    if (!this.excludedSubtreesURI.isEmpty()) {
      addLine(stringBuilder, "URI:");
      addLine(stringBuilder, this.excludedSubtreesURI.toString());
    } 
    if (!this.excludedSubtreesIP.isEmpty()) {
      addLine(stringBuilder, "IP:");
      addLine(stringBuilder, stringifyIPCollection(this.excludedSubtreesIP));
    } 
    if (!this.excludedSubtreesOtherName.isEmpty()) {
      addLine(stringBuilder, "OtherName:");
      addLine(stringBuilder, stringifyOtherNameCollection(this.excludedSubtreesOtherName));
    } 
    return stringBuilder.toString();
  }
}
