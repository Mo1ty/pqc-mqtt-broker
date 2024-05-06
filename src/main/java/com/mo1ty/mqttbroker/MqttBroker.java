package com.mo1ty.mqttbroker;

import com.hivemq.embedded.EmbeddedHiveMQ;
import com.hivemq.embedded.EmbeddedHiveMQBuilder;
import com.hivemq.embedded.internal.EmbeddedHiveMQBuilderImpl;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.interceptor.publish.PublishInboundInterceptor;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishInboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishInboundOutput;
import com.hivemq.extension.sdk.api.packets.general.UserProperties;
import com.hivemq.extension.sdk.api.packets.publish.AckReasonCode;
import com.hivemq.extension.sdk.api.packets.publish.PublishPacket;
import com.hivemq.util.Bytes;
import com.mo1ty.mqttbroker.crypto.CertVerify;
import com.mo1ty.mqttbroker.crypto.KyberBroker;
import com.mo1ty.mqttbroker.entity.EncryptedPayload;
import com.mo1ty.mqttbroker.entity.MqttMsgPayload;
import com.mo1ty.mqttbroker.entity.MessageStruct;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;


public class MqttBroker {

    public static void main(String[] args){
        KyberBroker kyberBroker = new KyberBroker();

        EmbeddedHiveMQBuilder hiveMqBuilder = new EmbeddedHiveMQBuilderImpl();

        HashMap<String, X509Certificate> certificateHashMap = new HashMap<>();
        HashMap<String, KeyPair> privateKeyHashMap = new HashMap<>();

        PublishInboundInterceptor publishInboundInterceptor = new PublishInboundInterceptor() {
            @Override
            public void onInboundPublish(@NotNull PublishInboundInput publishInboundInput, @NotNull PublishInboundOutput publishInboundOutput) {
                PublishPacket publishPacket = publishInboundInput.getPublishPacket();
                byte[] payload = Bytes.getBytesFromReadOnlyBuffer(publishPacket.getPayload());
                publishPacket.getUserProperties();

                MqttMsgPayload msgPayload = isCertPayload(payload);
                try{
                    if(msgPayload != null){
                        // VERIFY THE MESSAGE INTEGRITY. COMPARE HASHES.
                        // IF MESSAGE HASH IS RIGHT AND IT IS NOT AN INIT_CONN MESSAGE,
                        // END METHOD AND ALLOW IT TO BE PUBLISHED
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        InputStream in = new ByteArrayInputStream(msgPayload.x509Certificate);
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
                        CertVerify certVerify = new CertVerify();
                        if(!certVerify.verifyHashedMessage(cert.getPublicKey(), msgPayload.messageStruct.getBytes(), msgPayload.signature))
                            publishInboundOutput.preventPublishDelivery(AckReasonCode.PAYLOAD_FORMAT_INVALID);
                        else if(!msgPayload.messageStruct.plainMessage.contains("INIT_CONN_2"))
                            return;

                        // IF IT IS AN INIT_CONN MESSAGE, GENERATE KYBER KEYS,
                        // EDIT OUTPUT AND POST KYBER PUBKEY FOR PUBLISHER

                        String responseTopic = publishPacket.getResponseTopic()
                                .orElse(msgPayload.messageStruct.mqttTopic);
                        String deviceName = publishPacket.getUserProperties().getAllForName("DEVICE_IDENTIFIER").get(0);
                        KeyPair keyPair = kyberBroker.generateKeys();
                        privateKeyHashMap.put(deviceName, keyPair);

                        publishInboundOutput.getPublishPacket().setPayload(
                                ByteBuffer.wrap(keyPair.getPrivate().getEncoded())
                        );
                        publishInboundOutput.getPublishPacket().setTopic(responseTopic);
                        return;
                    }
                }
                catch (Exception e){
                    e.printStackTrace();
                }
                EncryptedPayload encryptedPayload = isEncryptedPayload(payload);
                try{
                    if(encryptedPayload != null){
                        // IF IT IS AN ENCRYPTED PAYLOAD ENTITY, DECYPHER IT,
                        // GENERATE NEW KYBER KEYS OR USE EXISTING IF WIRED TO
                        // INDIVIDUAL CONNECTIONS

                        String deviceName = publishPacket.getUserProperties().getAllForName("DEVICE_IDENTIFIER").get(0);
                        String encryptedMessage = encryptedPayload.encryptedMessage;
                        byte[] plainMessage = kyberBroker.decrypt(
                                privateKeyHashMap.get(deviceName).getPrivate(),
                                encryptedMessage.getBytes(StandardCharsets.UTF_8)
                        );
                        MessageStruct messageStruct = MessageStruct.getFromBytes(plainMessage);
                    }
                }
                catch (Exception e){
                    e.printStackTrace();
                }
            }
        };

        EmbeddedHiveMQ hiveMQ = hiveMqBuilder.build();


    }

    private static MqttMsgPayload isCertPayload(byte[] payload){
        try{
            return MqttMsgPayload.getFromJsonString(payload);
        }
        catch (Exception e){
            return null;
        }
    }

    private static EncryptedPayload isEncryptedPayload(byte[] payload){
        try{
            return EncryptedPayload.getFromJsonString(payload);
        }
        catch (Exception e){
            return null;
        }
    }

}
