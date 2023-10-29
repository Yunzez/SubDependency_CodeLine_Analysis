package com.encryption;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;



public class App {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        String text = "America runs on dunkin!";
        String key = "1234567812345678"; // 16 chars=128 bits

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");

        System.out.println("original text: " + text);
        // Encryption
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(text.getBytes());
        String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
        System.out.println("Encrypted: " + encryptedBase64);

        // Decryption
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedBase64));
        System.out.println("Decrypted: " + new String(decrypted));
    }
}
