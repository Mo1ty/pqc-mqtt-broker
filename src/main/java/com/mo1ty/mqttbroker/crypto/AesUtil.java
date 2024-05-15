package com.mo1ty.mqttbroker.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

public class AesUtil {

    public AesUtil(){
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public SecretKey generateAesKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    public byte[] encrypt(SecretKey secretKey, byte[] payload) throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] ivBytes = new byte[16];
        random.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
        byte[] aesEncryptedPayload = aesCipher.doFinal(payload);

        byte[] allByteArray = new byte[ivBytes.length + aesEncryptedPayload.length];

        ByteBuffer buff = ByteBuffer.wrap(allByteArray);
        buff.put(ivBytes);
        buff.put(aesEncryptedPayload);

        return buff.array();
    }

    public byte[] decrypt(SecretKey secretKey, byte[] payload) throws Exception {
        byte[] ivBytes = Arrays.copyOfRange(payload, 0, 16);
        byte[] message = Arrays.copyOfRange(payload, 16, payload.length);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(ivBytes));
        return aesCipher.doFinal(message);
    }
}
