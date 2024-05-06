package com.mo1ty.mqttbroker.entity;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.Serializable;

public class MqttMsgPayload implements Serializable {

    public MessageStruct messageStruct;
    public byte[] signature;
    public byte[] x509Certificate;

    public String toJsonString() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(this);
    }

    public static MqttMsgPayload getFromJsonString(byte[] jsonString) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.reader().readValue(jsonString, MqttMsgPayload.class);
    }
}
