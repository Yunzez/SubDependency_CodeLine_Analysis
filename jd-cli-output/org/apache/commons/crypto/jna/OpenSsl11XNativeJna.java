package org.apache.commons.crypto.jna;

import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.ptr.PointerByReference;
import java.nio.ByteBuffer;

class OpenSsl11XNativeJna {
  static final boolean INIT_OK;
  
  static final Throwable INIT_ERROR;
  
  public static native NativeLong ERR_peek_error();
  
  public static native String ERR_error_string(NativeLong paramNativeLong, char[] paramArrayOfchar);
  
  public static native PointerByReference EVP_CIPHER_CTX_new();
  
  public static native int EVP_CIPHER_CTX_set_padding(PointerByReference paramPointerByReference, int paramInt);
  
  public static native PointerByReference EVP_aes_128_cbc();
  
  public static native PointerByReference EVP_aes_128_ctr();
  
  public static native PointerByReference EVP_aes_192_cbc();
  
  public static native PointerByReference EVP_aes_192_ctr();
  
  public static native PointerByReference EVP_aes_256_cbc();
  
  public static native PointerByReference EVP_aes_256_ctr();
  
  public static native int EVP_CipherInit_ex(PointerByReference paramPointerByReference1, PointerByReference paramPointerByReference2, PointerByReference paramPointerByReference3, byte[] paramArrayOfbyte1, byte[] paramArrayOfbyte2, int paramInt);
  
  public static native int EVP_CipherUpdate(PointerByReference paramPointerByReference, ByteBuffer paramByteBuffer1, int[] paramArrayOfint, ByteBuffer paramByteBuffer2, int paramInt);
  
  public static native int EVP_CipherFinal_ex(PointerByReference paramPointerByReference, ByteBuffer paramByteBuffer, int[] paramArrayOfint);
  
  public static native void EVP_CIPHER_CTX_free(PointerByReference paramPointerByReference);
  
  public static native PointerByReference RAND_get_rand_method();
  
  public static native int RAND_bytes(ByteBuffer paramByteBuffer, int paramInt);
  
  public static native int ENGINE_finish(PointerByReference paramPointerByReference);
  
  public static native int ENGINE_free(PointerByReference paramPointerByReference);
  
  public static native int ENGINE_init(PointerByReference paramPointerByReference);
  
  public static native int ENGINE_set_default(PointerByReference paramPointerByReference, int paramInt);
  
  public static native PointerByReference ENGINE_by_id(String paramString);
  
  public static native String OpenSSL_version(int paramInt);
  
  static {
    boolean ok = false;
    Throwable thrown = null;
    try {
      String libName = System.getProperty("commons.crypto." + OpenSsl11XNativeJna.class.getSimpleName(), "crypto");
      OpenSslJna.debug("Native.register('%s')%n", new Object[] { libName });
      Native.register(libName);
      ok = true;
    } catch (Exception e) {
      thrown = e;
    } catch (UnsatisfiedLinkError e) {
      thrown = e;
    } finally {
      INIT_OK = ok;
      INIT_ERROR = thrown;
    } 
  }
}
