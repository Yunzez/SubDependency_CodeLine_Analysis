package org.apache.commons.crypto.jna;

import com.sun.jna.Function;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteBuffer;

class OpenSslNativeJna {
  static final int OPENSSL_INIT_ENGINE_RDRAND = 512;
  
  static final int OOSL_JNA_ENCRYPT_MODE = 1;
  
  static final int OOSL_JNA_DECRYPT_MODE = 0;
  
  static final boolean INIT_OK;
  
  static final Throwable INIT_ERROR;
  
  public static final long VERSION;
  
  public static final long VERSION_1_0_X = 268435456L;
  
  public static final long VERSION_1_1_X = 269484032L;
  
  static {
    String libraryName = System.getProperty("commons.crypto." + OpenSslNativeJna.class.getSimpleName(), "crypto");
    OpenSslJna.debug("NativeLibrary.getInstance('%s')%n", new Object[] { libraryName });
    NativeLibrary crypto = NativeLibrary.getInstance(libraryName);
    Function version = null;
    try {
      version = crypto.getFunction("SSLeay");
    } catch (UnsatisfiedLinkError unsatisfiedLinkError) {}
    if (version == null) {
      VERSION = 269484032L;
    } else {
      VERSION = 268435456L;
    } 
    if (VERSION == 269484032L) {
      INIT_OK = OpenSsl11XNativeJna.INIT_OK;
    } else {
      INIT_OK = OpenSsl10XNativeJna.INIT_OK;
    } 
    if (INIT_OK) {
      INIT_ERROR = null;
    } else if (VERSION == 269484032L) {
      INIT_ERROR = OpenSsl11XNativeJna.INIT_ERROR;
    } else {
      INIT_ERROR = OpenSsl10XNativeJna.INIT_ERROR;
    } 
  }
  
  public static PointerByReference ENGINE_by_id(String string) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.ENGINE_by_id(string); 
    return OpenSsl10XNativeJna.ENGINE_by_id(string);
  }
  
  public static void ENGINE_finish(PointerByReference rdrandEngine) {
    if (VERSION == 269484032L) {
      OpenSsl11XNativeJna.ENGINE_finish(rdrandEngine);
    } else {
      OpenSsl10XNativeJna.ENGINE_finish(rdrandEngine);
    } 
  }
  
  public static void ENGINE_free(PointerByReference rdrandEngine) {
    if (VERSION == 269484032L) {
      OpenSsl11XNativeJna.ENGINE_free(rdrandEngine);
    } else {
      OpenSsl10XNativeJna.ENGINE_free(rdrandEngine);
    } 
  }
  
  public static int ENGINE_init(PointerByReference rdrandEngine) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.ENGINE_init(rdrandEngine); 
    return OpenSsl10XNativeJna.ENGINE_init(rdrandEngine);
  }
  
  public static int ENGINE_set_default(PointerByReference rdrandEngine, int eNGINE_METHOD_RAND) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.ENGINE_set_default(rdrandEngine, eNGINE_METHOD_RAND); 
    return OpenSsl10XNativeJna.ENGINE_set_default(rdrandEngine, eNGINE_METHOD_RAND);
  }
  
  public static String ERR_error_string(NativeLong err, Object object) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.ERR_error_string(err, null); 
    return OpenSsl10XNativeJna.ERR_error_string(err, null);
  }
  
  public static NativeLong ERR_peek_error() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.ERR_peek_error(); 
    return OpenSsl10XNativeJna.ERR_peek_error();
  }
  
  public static PointerByReference EVP_aes_128_cbc() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_aes_128_cbc(); 
    return OpenSsl10XNativeJna.EVP_aes_128_cbc();
  }
  
  public static PointerByReference EVP_aes_128_ctr() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_aes_128_ctr(); 
    return OpenSsl10XNativeJna.EVP_aes_128_ctr();
  }
  
  public static PointerByReference EVP_aes_192_cbc() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_aes_192_cbc(); 
    return OpenSsl10XNativeJna.EVP_aes_192_cbc();
  }
  
  public static PointerByReference EVP_aes_192_ctr() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_aes_192_ctr(); 
    return OpenSsl10XNativeJna.EVP_aes_192_ctr();
  }
  
  public static PointerByReference EVP_aes_256_cbc() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_aes_256_cbc(); 
    return OpenSsl10XNativeJna.EVP_aes_256_cbc();
  }
  
  public static PointerByReference EVP_aes_256_ctr() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_aes_256_ctr(); 
    return OpenSsl10XNativeJna.EVP_aes_256_ctr();
  }
  
  public static void EVP_CIPHER_CTX_free(PointerByReference context) {
    if (VERSION == 269484032L) {
      OpenSsl11XNativeJna.EVP_CIPHER_CTX_free(context);
    } else {
      OpenSsl10XNativeJna.EVP_CIPHER_CTX_free(context);
    } 
  }
  
  public static PointerByReference EVP_CIPHER_CTX_new() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_CIPHER_CTX_new(); 
    return OpenSsl10XNativeJna.EVP_CIPHER_CTX_new();
  }
  
  public static void EVP_CIPHER_CTX_set_padding(PointerByReference context, int padding) {
    if (VERSION == 269484032L) {
      OpenSsl11XNativeJna.EVP_CIPHER_CTX_set_padding(context, padding);
    } else {
      OpenSsl10XNativeJna.EVP_CIPHER_CTX_set_padding(context, padding);
    } 
  }
  
  public static int EVP_CipherFinal_ex(PointerByReference context, ByteBuffer outBuffer, int[] outlen) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_CipherFinal_ex(context, outBuffer, outlen); 
    return OpenSsl10XNativeJna.EVP_CipherFinal_ex(context, outBuffer, outlen);
  }
  
  public static int EVP_CipherInit_ex(PointerByReference context, PointerByReference algo, Object object, byte[] encoded, byte[] iv, int cipherMode) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_CipherInit_ex(context, algo, null, encoded, iv, cipherMode); 
    return OpenSsl10XNativeJna.EVP_CipherInit_ex(context, algo, null, encoded, iv, cipherMode);
  }
  
  public static int EVP_CipherUpdate(PointerByReference context, ByteBuffer outBuffer, int[] outlen, ByteBuffer inBuffer, int remaining) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.EVP_CipherUpdate(context, outBuffer, outlen, inBuffer, remaining); 
    return OpenSsl10XNativeJna.EVP_CipherUpdate(context, outBuffer, outlen, inBuffer, remaining);
  }
  
  public static int RAND_bytes(ByteBuffer buf, int length) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.RAND_bytes(buf, length); 
    return OpenSsl10XNativeJna.RAND_bytes(buf, length);
  }
  
  public static PointerByReference RAND_get_rand_method() {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.RAND_get_rand_method(); 
    return OpenSsl10XNativeJna.RAND_get_rand_method();
  }
  
  public static PointerByReference RAND_SSLeay() {
    if (VERSION == 269484032L)
      return null; 
    return OpenSsl10XNativeJna.RAND_SSLeay();
  }
  
  public static String OpenSSLVersion(int i) {
    if (VERSION == 269484032L)
      return OpenSsl11XNativeJna.OpenSSL_version(i); 
    return OpenSsl10XNativeJna.SSLeay_version(i);
  }
  
  public static void ENGINE_load_rdrand() {
    if (VERSION == 269484032L)
      return; 
    OpenSsl10XNativeJna.ENGINE_load_rdrand();
  }
  
  public static void ENGINE_cleanup() {
    if (VERSION == 269484032L)
      return; 
    OpenSsl10XNativeJna.ENGINE_cleanup();
  }
  
  public static void EVP_CIPHER_CTX_cleanup(PointerByReference context) {
    if (VERSION == 269484032L)
      return; 
    OpenSsl10XNativeJna.EVP_CIPHER_CTX_cleanup(context);
  }
}
