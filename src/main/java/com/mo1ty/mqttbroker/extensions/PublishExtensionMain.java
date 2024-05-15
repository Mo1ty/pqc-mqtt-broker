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
import com.mo1ty.mqttbroker.crypto.AesUtil;
import com.mo1ty.mqttbroker.crypto.CertVerify;
import com.mo1ty.mqttbroker.crypto.KyberBroker;
import com.mo1ty.mqttbroker.entity.EncryptedPayload;
import com.mo1ty.mqttbroker.entity.MessageStruct;
import com.mo1ty.mqttbroker.entity.MqttMsgPayload;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class PublishExtensionMain implements ExtensionMain {

    private HashMap<String, X509Certificate> certificateHashMap = new HashMap<>();
    private HashMap<String, KeyPair> privateKeyHashMap = new HashMap<>();
    private HashMap<String, PublicKey> publicKeyHashMap = new HashMap<>();
    private final CertVerify certVerify = new CertVerify();
    private final KyberBroker kyberBroker = new KyberBroker();
    private final AesUtil aesUtil = new AesUtil();

    private HashMap<String, SecretKey> secretKeyHashMap = new HashMap<>();

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
            String deviceName = publishInboundInput.getClientInformation().getClientId();

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
                    certificateHashMap.put(deviceName, cert);
                    privateKeyHashMap.put(deviceName, keyPair);

                    publishInboundOutput.getPublishPacket().setPayload(
                            ByteBuffer.wrap(keyPair.getPublic().getEncoded())
                    );
                    publishInboundOutput.getPublishPacket().setTopic(responseTopic);
                    publishInboundOutput.getPublishPacket().getUserProperties().addUserProperty("is_request_response", "true");
                    publishInboundOutput.getPublishPacket().getUserProperties().addUserProperty("requires_encryption", "false");
                    System.out.println("PACKET DELIVERED AND SAVED!");
                    return;
                }
            }
            catch (Exception e){
                e.printStackTrace();
            }

            EncryptedPayload encryptedPayload = isEncryptedPayload(payload);
            try{
                if(encryptedPayload != null){
                    // Validate payload using certificate
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    InputStream in = new ByteArrayInputStream(encryptedPayload.x509Certificate);
                    X509Certificate encryptedCert = (X509Certificate) cf.generateCertificate(in);

                    boolean isSignatureValid = !encryptedPayload.algorithmIdentifier.contains("AES")
                            ? certVerify.verifyHashedMessage(encryptedCert.getPublicKey(), encryptedPayload.encryptedMessage, encryptedPayload.signature)
                            : certVerify.verifyHashedMessage(encryptedCert.getPublicKey(), aesUtil.decrypt(secretKeyHashMap.get(deviceName), encryptedPayload.encryptedMessage), encryptedPayload.signature);

                    /*
                    if(!isSignatureValid){
                        publishInboundOutput.preventPublishDelivery(AckReasonCode.NOT_AUTHORIZED);
                        return;
                    }
                    */

                    // Get user properties and encrypted message itself
                    byte[] encryptedMessage = encryptedPayload.encryptedMessage;

                    // If algorithm is set to "kyber", unwrap the AES key, store it and set request response
                    if(encryptedPayload.algorithmIdentifier.contains("kyber")){
                        SecretKey secretKey = (SecretKey) kyberBroker.unwrap(
                                privateKeyHashMap.get(deviceName).getPrivate(),
                                encryptedMessage);
                        secretKeyHashMap.put(deviceName, secretKey);

                        String aesResponseTopic = publishInboundInput.getPublishPacket().getResponseTopic()
                                .orElse(publishInboundInput.getPublishPacket().getTopic());
                        publishInboundOutput.getPublishPacket().setPayload(
                                ByteBuffer.wrap("SUCCESS".getBytes(StandardCharsets.UTF_8))
                        );
                        publishInboundOutput.getPublishPacket().setTopic(aesResponseTopic);
                        publishInboundOutput.getPublishPacket().getUserProperties().addUserProperty("is_request_response", "true");
                        publishInboundOutput.getPublishPacket().getUserProperties().addUserProperty("requires_encryption", "false");
                        System.out.println("PACKET DELIVERED AND SAVED!");
                        return;
                    }

                    // decrypt payload and create entity for publish
                    byte[] plainMessage = aesUtil.decrypt(secretKeyHashMap.get(deviceName), encryptedMessage);
                    String plainMsg = new String(plainMessage);
                    MessageStruct messageStruct = MessageStruct.getFromBytes(plainMessage);
                    MqttMsgPayload mqttMsgPayload = new MqttMsgPayload(
                            messageStruct,
                            encryptedPayload.signature,
                            encryptedPayload.x509Certificate);

                    // set publish packet with required user properties
                    publishInboundOutput.getPublishPacket().setPayload(
                            ByteBuffer.wrap(plainMessage)
                    );
                    publishInboundOutput.getPublishPacket().setTopic(publishPacket.getTopic());
                    publishInboundOutput.getPublishPacket().getUserProperties().addUserProperty("is_request_response", "false");
                    publishInboundOutput.getPublishPacket().getUserProperties().addUserProperty("requires_encryption", "true");
                    System.out.println("AES PACKET DELIVERED AND SAVED!");
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


            if(packet.getUserProperties().getAllForName("is_request_response").get(0).equals("true"))
                return;
            else if(packet.getUserProperties().getAllForName("requires_encryption").get(0).equals("true")
                    && !secretKeyHashMap.containsKey(clientId))
                publishOutboundOutput.preventPublishDelivery();

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
                EncryptedPayload encryptedPayload = new EncryptedPayload(encryptedData, "AES");
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
