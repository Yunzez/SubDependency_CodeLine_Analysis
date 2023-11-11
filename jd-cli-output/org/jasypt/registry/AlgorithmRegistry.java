package org.jasypt.registry;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class AlgorithmRegistry {
  public static Set getAllDigestAlgorithms() {
    List<String> algos = new ArrayList<String>(Security.getAlgorithms("MessageDigest"));
    Collections.sort(algos);
    return Collections.unmodifiableSet(new LinkedHashSet(algos));
  }
  
  public static Set getAllPBEAlgorithms() {
    List<String> algos = new ArrayList<String>(Security.getAlgorithms("Cipher"));
    Collections.sort(algos);
    LinkedHashSet<String> pbeAlgos = new LinkedHashSet();
    Iterator<String> algosIter = algos.iterator();
    while (algosIter.hasNext()) {
      String algo = algosIter.next();
      if (algo != null && algo.startsWith("PBE"))
        pbeAlgos.add(algo); 
    } 
    return Collections.unmodifiableSet(pbeAlgos);
  }
}
