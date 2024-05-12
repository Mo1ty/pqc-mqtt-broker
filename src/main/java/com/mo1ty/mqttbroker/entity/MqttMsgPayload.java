package com.mo1ty.mqttbroker.entity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hivemq.util.Bytes;

import java.io.Serializable;
import java.nio.ByteBuffer;
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
        String jsonStr = new String(jsonString, StandardCharsets.UTF_8);
        return objectMapper.reader().readValue(jsonStr, MqttMsgPayload.class);
    }
}
