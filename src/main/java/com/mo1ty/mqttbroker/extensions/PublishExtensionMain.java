package com.mo1ty.mqttbroker.extensions;

import com.hivemq.extension.sdk.api.ExtensionMain;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.client.ClientContext;
import com.hivemq.extension.sdk.api.client.parameter.InitializerInput;
import com.hivemq.extension.sdk.api.interceptor.publish.PublishInboundInterceptor;
import com.hivemq.extension.sdk.api.interceptor.publish.PublishOutboundInterceptor;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishInboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishInboundOutput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundOutput;
import com.hivemq.extension.sdk.api.packets.publish.AckReasonCode;
import com.hivemq.extension.sdk.api.packets.publish.PublishPacket;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartOutput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopOutput;
import com.hivemq.extension.sdk.api.services.Services;
import com.hivemq.extension.sdk.api.services.intializer.ClientInitializer;
import com.hivemq.extension.sdk.api.services.intializer.InitializerRegistry;
import com.hivemq.util.Bytes;
import com.mo1ty.mqttbroker.crypto.CertVerify;
import com.mo1ty.mqttbroker.crypto.KyberBroker;
import com.mo1ty.mqttbroker.entity.EncryptedPayload;
import com.mo1ty.mqttbroker.entity.MqttMsgPayload;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;

public class PublishExtensionMain implements ExtensionMain {

    private HashMap<String, X509Certificate> certificateHashMap = new HashMap<>();
    private HashMap<String, KeyPair> privateKeyHashMap = new HashMap<>();
    private HashMap<String, PublicKey> publicKeyHashMap = new HashMap<>();
    private final CertVerify certVerify = new CertVerify();
    private final KyberBroker kyberBroker = new KyberBroker();

    @Override
    public void extensionStart(ExtensionStartInput input, ExtensionStartOutput output) {

        //create shareable interceptor
        final PublishInboundInterceptor customInboundInterceptor = new CustomInboundInterceptor();
        final PublishOutboundInterceptor customOutboundInterceptor = new CustomOutboundInterceptor();

        //create client initializer
        final ClientInitializer initializer = new ClientInitializer() {

            @Override
            public void initialize(@NotNull InitializerInput initializerInput, @NotNull ClientContext clientContext) {
                //add shareable interceptor
                clientContext.addPublishInboundInterceptor(customInboundInterceptor);
                clientContext.addPublishOutboundInterceptor(customOutboundInterceptor);
            }
        };

        //get registry from Services
        final InitializerRegistry initializerRegistry = Services.initializerRegistry();

        //set client initializer
        initializerRegistry.setClientInitializer(initializer);
    }

    @Override
    public void extensionStop(ExtensionStopInput input, ExtensionStopOutput output) {
        //Code to run when extension is stopped
    }

    private class CustomInboundInterceptor implements PublishInboundInterceptor {

        @Override
        public void onInboundPublish(@NotNull PublishInboundInput publishInboundInput, @NotNull PublishInboundOutput publishInboundOutput) {
            PublishPacket publishPacket = publishInboundInput.getPublishPacket();
            byte[] payload = Bytes.getBytesFromReadOnlyBuffer(publishPacket.getPayload());
            String clientId = publishInboundInput.getClientInformation().getClientId();

            MqttMsgPayload msgPayload = isCertPayload(payload);
            try{
                if(msgPayload != null){
                    // VERIFY THE MESSAGE INTEGRITY. COMPARE HASHES.
                    // IF MESSAGE HASH IS RIGHT AND IT IS NOT AN INIT_CONN MESSAGE,
                    // END METHOD AND ALLOW IT TO BE PUBLISHED
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    InputStream in = new ByteArrayInputStream(msgPayload.x509Certificate);
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(in);

                    if(!certVerify.verifyHashedMessage(cert.getPublicKey(), msgPayload.messageStruct.toJsonStringAsBytes(), msgPayload.signature)) {
                        publishInboundOutput.preventPublishDelivery(AckReasonCode.UNSPECIFIED_ERROR);
                        return;
                    }
                    else if(!msgPayload.messageStruct.plainMessage.contains("INIT_CONN_2"))
                        return;

                    // IF IT IS AN INIT_CONN MESSAGE, GENERATE KYBER KEYS,
                    // EDIT OUTPUT AND POST KYBER PUBKEY FOR PUBLISHER

                    String responseTopic = publishPacket.getResponseTopic()
                            .orElse(msgPayload.messageStruct.mqttTopic);
                    KeyPair keyPair = kyberBroker.generateKeys();
                    certificateHashMap.put(clientId, cert);
                    privateKeyHashMap.put(clientId, keyPair);

                    publishInboundOutput.getPublishPacket().setPayload(
                            ByteBuffer.wrap(keyPair.getPrivate().getEncoded())
                    );
                    publishInboundOutput.getPublishPacket().setTopic(responseTopic);
                    System.out.println("PACKET DELIVERED AND SAVED!");
                    return;
                }
            }
            catch (Exception e){
                e.printStackTrace();
            }

            //
            EncryptedPayload encryptedPayload = isEncryptedPayload(payload);
            try{
                if(encryptedPayload != null){
                    // IF IT IS AN ENCRYPTED PAYLOAD ENTITY, DECRYPT IT,
                    // GENERATE NEW KYBER KEYS OR USE EXISTING IF WIRED TO
                    // INDIVIDUAL CONNECTIONS

                    String deviceName = publishPacket.getUserProperties().getAllForName("DEVICE_IDENTIFIER").get(0);
                    String encryptedMessage = encryptedPayload.encryptedMessage;
                    byte[] plainMessage = kyberBroker.decrypt(
                            privateKeyHashMap.get(deviceName).getPrivate(),
                            encryptedMessage.getBytes(StandardCharsets.UTF_8)
                    );
                    MqttMsgPayload mqttMsgPayload = MqttMsgPayload.getFromJsonString(plainMessage);
                    return;
                }
            }
            catch (Exception e){
                e.printStackTrace();
            }

            // IF THIS MESSAGE IS NONE OF THESE, MESSAGE IS NOT DELIVERED
            publishInboundOutput.preventPublishDelivery(
                    AckReasonCode.UNSPECIFIED_ERROR
            );
            System.out.println("PACKET NOT DELIVERED!");
        }
    }

    private class CustomOutboundInterceptor implements PublishOutboundInterceptor {

        @Override
        public void onOutboundPublish(@NotNull PublishOutboundInput publishOutboundInput, @NotNull PublishOutboundOutput publishOutboundOutput) {
            PublishPacket packet = publishOutboundInput.getPublishPacket();
            String clientId = publishOutboundInput.getClientInformation().getClientId();


            // DATA IN BROKER'S PERSISTENCE WILL ALWAYS BE UNENCRYPTED BUT SIGNED
            // IN THIS CASE, IT WILL BE TRANSLATED FROM BUFFER TO OBJECT, ENCRYPTED,
            // AND SENT AS ENCRYPTED PAYLOAD IF KEY WAS FOUND
            MqttMsgPayload payload = isCertPayload(Bytes.getBytesFromReadOnlyBuffer(packet.getPayload()));
            if(payload == null){
                publishOutboundOutput.preventPublishDelivery();
                return;
            }

            try {
                // IF PUBLIC KEY IS NOT FOUND, DATA WILL BE SENT UNENCRYPTED
                // WITH SECURITY LEVEL 1 STANDARD
                PublicKey publicKey = publicKeyHashMap.get(clientId);
                if(publicKey == null){
                    return;
                }

                byte[] encryptedData = kyberBroker.encrypt(publicKey, payload.toJsonString());
                EncryptedPayload encryptedPayload = new EncryptedPayload(encryptedData.toString(), "Kyber-1024");
                publishOutboundOutput.getPublishPacket().setPayload(
                        ByteBuffer.wrap(
                                encryptedPayload.toJsonString().getBytes(StandardCharsets.UTF_8)
                        )
                );
            }
            catch (Exception e){
                e.printStackTrace();
            }
        }
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
