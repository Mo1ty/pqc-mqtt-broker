package com.mo1ty.mqttbroker.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class FalconVerify implements CertVerify {

    public FalconVerify(){
        if(Security.getProvider("BC") == null){
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public byte[] signMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature falconSign = Signature.getInstance("Falcon-512", "BC");
        falconSign.initSign(keyPair.getPrivate());
        falconSign.update(message);
        byte[] signature = falconSign.sign();
        return signature;
    }

    public byte[] hashAndSignMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature falconSign = Signature.getInstance("Falcon-512", "BC");
        falconSign.initSign(keyPair.getPrivate());
        byte[] digestedMessage = messageDigest.digest(message);
        falconSign.update(digestedMessage);
        return falconSign.sign();
    }

    public boolean verifyMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        Signature falconVerify = Signature.getInstance("Falcon-512", "BC");
        falconVerify.initVerify(publicKey);
        falconVerify.update(message);
        return falconVerify.verify(signature);
    }

    public boolean verifyHashedMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA3-512");
        Signature falconVerify = Signature.getInstance("Falcon-512", "BC");
        falconVerify.initVerify(publicKey);
        byte[] digestedMessage = messageDigest.digest(message);
        falconVerify.update(digestedMessage);
        return falconVerify.verify(signature);
    }

}
