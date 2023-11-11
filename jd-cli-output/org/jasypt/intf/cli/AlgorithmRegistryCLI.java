package org.jasypt.intf.cli;

import java.util.Set;
import org.jasypt.registry.AlgorithmRegistry;

public final class AlgorithmRegistryCLI {
  public static void main(String[] args) {
    try {
      Set digestAlgos = AlgorithmRegistry.getAllDigestAlgorithms();
      Set pbeAlgos = AlgorithmRegistry.getAllPBEAlgorithms();
      System.out.println();
      System.out.println("DIGEST ALGORITHMS:   " + digestAlgos);
      System.out.println();
      System.out.println("PBE ALGORITHMS:      " + pbeAlgos);
      System.out.println();
    } catch (Throwable t) {
      t.printStackTrace(System.err);
    } 
  }
}
