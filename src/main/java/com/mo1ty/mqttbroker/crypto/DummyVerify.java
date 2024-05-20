package com.mo1ty.mqttbroker.crypto;

import java.security.*;

public class DummyVerify implements CertVerify {
    @Override
    public byte[] signMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return new byte[0];
    }

    @Override
    public byte[] hashAndSignMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return new byte[0];
    }

    @Override
    public boolean verifyMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return true;
    }

    @Override
    public boolean verifyHashedMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        return true;
    }
}
