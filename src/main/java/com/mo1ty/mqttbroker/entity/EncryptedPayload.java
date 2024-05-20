package com.mo1ty.mqttbroker.entity;

import com.fasterxml.jackson.databind.ObjectMapper;

public class EncryptedPayload {

    public byte[] encryptedMessage;
    public String algorithmIdentifier;
    public byte[] signature;
    public byte[] x509Certificate;

    public String toJsonString() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(this);
    }

    public static EncryptedPayload getFromJsonString(byte[] jsonString) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(jsonString, EncryptedPayload.class);
    }

    public EncryptedPayload(byte[] encryptedMessage, String algorithmIdentifier) {
        this.encryptedMessage = encryptedMessage;
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public EncryptedPayload(byte[] encryptedMessage, String algorithmIdentifier, byte[] signature, byte[] x509Certificate) {
        this.encryptedMessage = encryptedMessage;
        this.algorithmIdentifier = algorithmIdentifier;
        this.signature = signature;
        this.x509Certificate = x509Certificate;
    }

    public EncryptedPayload() {
    }

    public byte[] getEncryptedMessage() {
        return encryptedMessage;
    }

    public void setEncryptedMessage(byte[] encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public String getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public void setAlgorithmIdentifier(String algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }
}
