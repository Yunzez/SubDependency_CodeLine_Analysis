package org.apache.commons.crypto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.CopyOption;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFileAttributes;
import java.util.Objects;
import java.util.Properties;
import java.util.UUID;
import org.apache.commons.crypto.utils.Utils;

final class NativeCodeLoader {
  private static final int EOF = -1;
  
  private static final Throwable loadingError = loadLibrary();
  
  private static final boolean nativeCodeLoaded = (loadingError == null);
  
  private static BufferedInputStream buffer(InputStream inputStream) {
    Objects.requireNonNull(inputStream, "inputStream");
    return (inputStream instanceof BufferedInputStream) ? (BufferedInputStream)inputStream : new BufferedInputStream(inputStream);
  }
  
  private static boolean contentsEquals(InputStream input1, InputStream input2) throws IOException {
    if (input1 == input2)
      return true; 
    if ((((input1 == null) ? 1 : 0) ^ ((input2 == null) ? 1 : 0)) != 0)
      return false; 
    BufferedInputStream bufferedInput1 = buffer(input1);
    BufferedInputStream bufferedInput2 = buffer(input2);
    int ch = bufferedInput1.read();
    while (-1 != ch) {
      int ch2 = bufferedInput2.read();
      if (ch != ch2)
        return false; 
      ch = bufferedInput1.read();
    } 
    return (bufferedInput2.read() == -1);
  }
  
  private static void debug(String format, Object... args) {
    if (isDebug()) {
      System.out.println(String.format(format, args));
      if (args != null && args.length > 0 && args[0] instanceof Throwable)
        ((Throwable)args[0]).printStackTrace(System.out); 
    } 
  }
  
  private static File extractLibraryFile(String libFolderForCurrentOS, String libraryFileName, String targetFolder) {
    String nativeLibraryFilePath = libFolderForCurrentOS + "/" + libraryFileName;
    UUID uuid = UUID.randomUUID();
    String extractedLibFileName = String.format("commons-crypto-%s-%s", new Object[] { uuid, libraryFileName });
    File extractedLibFile = new File(targetFolder, extractedLibFileName);
    debug("Extracting '%s' to '%s'...", new Object[] { nativeLibraryFilePath, extractedLibFile });
    try (InputStream inputStream = NativeCodeLoader.class.getResourceAsStream(nativeLibraryFilePath)) {
      if (inputStream == null) {
        debug("Resource not found: %s", new Object[] { nativeLibraryFilePath });
        return null;
      } 
      try {
        Path path = extractedLibFile.toPath();
        long byteCount = Files.copy(inputStream, path, new CopyOption[] { StandardCopyOption.REPLACE_EXISTING });
        if (isDebug()) {
          debug("Extracted '%s' to '%s': %,d bytes [%s]", new Object[] { nativeLibraryFilePath, extractedLibFile, Long.valueOf(byteCount), 
                Files.isExecutable(path) ? "X+" : "X-" });
          PosixFileAttributes attributes = Files.<PosixFileAttributes>readAttributes(path, PosixFileAttributes.class, new java.nio.file.LinkOption[0]);
          if (attributes != null)
            debug("Attributes '%s': %s %s %s", new Object[] { extractedLibFile, attributes.permissions(), attributes
                  .owner(), attributes.group() }); 
        } 
      } finally {
        debug("Delete on exit: %s", new Object[] { extractedLibFile });
        extractedLibFile.deleteOnExit();
      } 
      if (!extractedLibFile.setReadable(true) || !extractedLibFile.setExecutable(true) || 
        !extractedLibFile.setWritable(true, true))
        throw new IllegalStateException("Invalid path for library path " + extractedLibFile); 
      try(InputStream nativeInputStream = NativeCodeLoader.class.getResourceAsStream(nativeLibraryFilePath); 
          InputStream extractedLibIn = new FileInputStream(extractedLibFile)) {
        debug("Validating '%s'...", new Object[] { extractedLibFile });
        if (!contentsEquals(nativeInputStream, extractedLibIn))
          throw new IllegalStateException(String.format("Failed to write a native library file %s to %s", new Object[] { nativeLibraryFilePath, extractedLibFile })); 
      } 
      return extractedLibFile;
    } catch (IOException e) {
      debug("Ignoring %s", new Object[] { e });
      return null;
    } 
  }
  
  private static File findNativeLibrary() {
    Properties props = Utils.getDefaultProperties();
    String nativeLibraryPath = props.getProperty("commons.crypto.lib.path");
    String nativeLibraryName = props.getProperty("commons.crypto.lib.name");
    if (nativeLibraryName == null)
      nativeLibraryName = System.mapLibraryName("commons-crypto"); 
    if (nativeLibraryPath != null) {
      File nativeLib = new File(nativeLibraryPath, nativeLibraryName);
      if (nativeLib.exists())
        return nativeLib; 
    } 
    nativeLibraryPath = "/org/apache/commons/crypto/native/" + OsInfo.getNativeLibFolderPathForCurrentOS();
    boolean hasNativeLib = hasResource(nativeLibraryPath + "/" + nativeLibraryName);
    if (!hasNativeLib) {
      String altName = "libcommons-crypto.jnilib";
      if (OsInfo.getOSName().equals("Mac") && hasResource(nativeLibraryPath + "/" + "libcommons-crypto.jnilib")) {
        nativeLibraryName = "libcommons-crypto.jnilib";
        hasNativeLib = true;
      } 
    } 
    if (!hasNativeLib) {
      String errorMessage = String.format("No native library is found for os.name=%s and os.arch=%s", new Object[] { OsInfo.getOSName(), OsInfo.getArchName() });
      throw new IllegalStateException(errorMessage);
    } 
    String tempFolder = (new File(props.getProperty("commons.crypto.lib.tempdir", System.getProperty("java.io.tmpdir")))).getAbsolutePath();
    return extractLibraryFile(nativeLibraryPath, nativeLibraryName, tempFolder);
  }
  
  static Throwable getLoadingError() {
    return loadingError;
  }
  
  private static boolean hasResource(String path) {
    return (NativeCodeLoader.class.getResource(path) != null);
  }
  
  private static boolean isDebug() {
    return Boolean.getBoolean("commons.crypto.debug");
  }
  
  static boolean isNativeCodeLoaded() {
    return nativeCodeLoaded;
  }
  
  static Throwable loadLibrary() {
    try {
      File nativeLibFile = findNativeLibrary();
      if (nativeLibFile != null) {
        String absolutePath = nativeLibFile.getAbsolutePath();
        debug("System.load('%s')", new Object[] { absolutePath });
        System.load(absolutePath);
      } else {
        String libname = "commons-crypto";
        debug("System.loadLibrary('%s')", new Object[] { "commons-crypto" });
        System.loadLibrary("commons-crypto");
      } 
      return null;
    } catch (Exception t) {
      return t;
    } catch (UnsatisfiedLinkError t) {
      return t;
    } 
  }
}
