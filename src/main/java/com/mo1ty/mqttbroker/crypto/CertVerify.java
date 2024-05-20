package com.mo1ty.mqttbroker.crypto;

import java.security.*;

public interface CertVerify {

    byte[] signMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException;

    byte[] hashAndSignMessage(KeyPair keyPair, byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException;

    boolean verifyMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException;

    boolean verifyHashedMessage(PublicKey publicKey, byte[] message, byte[] signature) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException;

}
