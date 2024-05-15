package com.mo1ty.mqttbroker.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.*;

public class KyberBroker {

    public KyberBroker(){
        if(Security.getProvider("BCPQC") == null){
            Security.addProvider(new BouncyCastlePQCProvider());
        }
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public KeyPair generateKeys() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("kyber1024", "BCPQC");
        keyPairGenerator.initialize(KyberParameterSpec.kyber1024, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] decrypt(PrivateKey privateKey, byte[] payload) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("kyber1024", "BCPQC");
        encryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return encryptionCipher.doFinal(payload);
    }

    public byte[] encrypt(PublicKey publicKey, byte[] payload) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("kyber1024", "BCPQC");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptionCipher.doFinal(payload);
    }

    public byte[] wrap(PublicKey publicKey, SecretKey secret) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("kyber1024", "BCPQC");
        encryptionCipher.init(Cipher.WRAP_MODE, publicKey);
        return encryptionCipher.wrap(secret);
    }

    public Key unwrap(PrivateKey privateKey, byte[] payload) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("kyber1024", "BCPQC");
        encryptionCipher.init(Cipher.UNWRAP_MODE, privateKey);
        return encryptionCipher.unwrap(payload, "AES", Cipher.SECRET_KEY);
    }

}
