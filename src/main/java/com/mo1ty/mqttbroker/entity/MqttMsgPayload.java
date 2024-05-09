package com.mo1ty.mqttbroker.entity;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;

public class MqttMsgPayload implements Serializable {

    public MessageStruct messageStruct;
    public byte[] signature;
    public byte[] x509Certificate;

    public byte[] toJsonString() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(this).getBytes(StandardCharsets.UTF_8);
    }

    public static MqttMsgPayload getFromJsonString(byte[] jsonString) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(jsonString, MqttMsgPayload.class);
    }
}
