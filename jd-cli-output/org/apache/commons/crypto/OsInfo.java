package org.apache.commons.crypto;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;

final class OsInfo {
  private static final HashMap<String, String> archMapping = new HashMap<>();
  
  static final String X86 = "x86";
  
  static final String X86_64 = "x86_64";
  
  static final String IA64_32 = "ia64_32";
  
  static final String IA64 = "ia64";
  
  static final String PPC = "ppc";
  
  static final String PPC64 = "ppc64";
  
  static {
    archMapping.put("x86", "x86");
    archMapping.put("i386", "x86");
    archMapping.put("i486", "x86");
    archMapping.put("i586", "x86");
    archMapping.put("i686", "x86");
    archMapping.put("pentium", "x86");
    archMapping.put("x86_64", "x86_64");
    archMapping.put("amd64", "x86_64");
    archMapping.put("em64t", "x86_64");
    archMapping.put("universal", "x86_64");
    archMapping.put("ia64", "ia64");
    archMapping.put("ia64w", "ia64");
    archMapping.put("ia64_32", "ia64_32");
    archMapping.put("ia64n", "ia64_32");
    archMapping.put("ppc", "ppc");
    archMapping.put("power", "ppc");
    archMapping.put("powerpc", "ppc");
    archMapping.put("power_pc", "ppc");
    archMapping.put("power_rs", "ppc");
    archMapping.put("ppc64", "ppc64");
    archMapping.put("power64", "ppc64");
    archMapping.put("powerpc64", "ppc64");
    archMapping.put("power_pc64", "ppc64");
    archMapping.put("power_rs64", "ppc64");
  }
  
  public static void main(String[] args) {
    if (args.length >= 1) {
      if ("--os".equals(args[0])) {
        System.out.print(getOSName());
        return;
      } 
      if ("--arch".equals(args[0])) {
        System.out.print(getArchName());
        return;
      } 
    } 
    System.out.print(getNativeLibFolderPathForCurrentOS());
  }
  
  static String getNativeLibFolderPathForCurrentOS() {
    return getOSName() + "/" + getArchName();
  }
  
  static String getOSName() {
    return translateOSNameToFolderName(System.getProperty("os.name"));
  }
  
  static String getArchName() {
    String osArch = System.getProperty("os.arch");
    if (osArch.startsWith("arm") && System.getProperty("os.name").contains("Linux")) {
      String javaHome = System.getProperty("java.home");
      try {
        String[] cmdarray = { "/bin/sh", "-c", "find '" + javaHome + "' -name 'libjvm.so' | head -1 | xargs readelf -A | grep 'Tag_ABI_VFP_args: VFP registers'" };
        int exitCode = Runtime.getRuntime().exec(cmdarray).waitFor();
        if (exitCode == 0)
          return "armhf"; 
      } catch (IOException iOException) {
      
      } catch (InterruptedException interruptedException) {}
    } else {
      String lc = osArch.toLowerCase(Locale.US);
      if (archMapping.containsKey(lc))
        return archMapping.get(lc); 
    } 
    return translateArchNameToFolderName(osArch);
  }
  
  private static String translateOSNameToFolderName(String osName) {
    if (osName.contains("Windows"))
      return "Windows"; 
    if (osName.contains("Mac"))
      return "Mac"; 
    if (osName.contains("Linux"))
      return "Linux"; 
    if (osName.contains("AIX"))
      return "AIX"; 
    return osName.replaceAll("\\W", "");
  }
  
  private static String translateArchNameToFolderName(String archName) {
    return archName.replaceAll("\\W", "");
  }
}
