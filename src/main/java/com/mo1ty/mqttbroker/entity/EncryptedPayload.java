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
}
