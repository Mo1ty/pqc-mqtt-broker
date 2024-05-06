package com.mo1ty.mqttbroker.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;

import javax.crypto.Cipher;
import java.security.*;

public class KyberBroker {

    public KyberBroker(){
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public KeyPair generateKeys() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Kyber-1024", "BC");
        keyPairGenerator.initialize(KyberParameterSpec.kyber1024, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] decrypt(PrivateKey privateKey, byte[] payload) throws Exception {
        Cipher encryptionCipher = Cipher.getInstance("Kyber-1024", "BC");
        encryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return encryptionCipher.doFinal(payload);
    }

}
