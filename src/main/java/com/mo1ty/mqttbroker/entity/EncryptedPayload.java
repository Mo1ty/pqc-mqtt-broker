package com.mo1ty.mqttbroker.entity;

import com.fasterxml.jackson.databind.ObjectMapper;

public class EncryptedPayload {

    public String encryptedMessage;
    public String algorithmIdentifier;

    public String toJsonString() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(this);
    }

    public static EncryptedPayload getFromJsonString(byte[] jsonString) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(jsonString, EncryptedPayload.class);
    }

    public EncryptedPayload(String encryptedMessage, String algorithmIdentifier) {
        this.encryptedMessage = encryptedMessage;
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public EncryptedPayload() {
    }

    public String getEncryptedMessage() {
        return encryptedMessage;
    }

    public void setEncryptedMessage(String encryptedMessage) {
        this.encryptedMessage = encryptedMessage;
    }

    public String getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public void setAlgorithmIdentifier(String algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }
}
