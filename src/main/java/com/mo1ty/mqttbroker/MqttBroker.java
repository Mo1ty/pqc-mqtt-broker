package com.mo1ty.mqttbroker;

import com.hivemq.embedded.EmbeddedExtension;
import com.hivemq.embedded.EmbeddedExtensionBuilder;
import com.hivemq.embedded.EmbeddedHiveMQ;
import com.hivemq.embedded.EmbeddedHiveMQBuilder;
import com.hivemq.embedded.internal.EmbeddedExtensionBuilderImpl;
import com.hivemq.embedded.internal.EmbeddedHiveMQBuilderImpl;
import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.client.ClientContext;
import com.hivemq.extension.sdk.api.client.parameter.ClientInformation;
import com.hivemq.extension.sdk.api.client.parameter.InitializerInput;
import com.hivemq.extension.sdk.api.interceptor.publish.PublishInboundInterceptor;
import com.hivemq.extension.sdk.api.interceptor.publish.PublishOutboundInterceptor;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishInboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishInboundOutput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundInput;
import com.hivemq.extension.sdk.api.interceptor.publish.parameter.PublishOutboundOutput;
import com.hivemq.extension.sdk.api.packets.general.UserProperties;
import com.hivemq.extension.sdk.api.packets.publish.AckReasonCode;
import com.hivemq.extension.sdk.api.packets.publish.PublishPacket;
import com.hivemq.extension.sdk.api.services.Services;
import com.hivemq.extension.sdk.api.services.intializer.ClientInitializer;
import com.hivemq.extension.sdk.api.services.intializer.InitializerRegistry;
import com.hivemq.util.Bytes;
import com.mo1ty.mqttbroker.crypto.CertVerify;
import com.mo1ty.mqttbroker.crypto.KyberBroker;
import com.mo1ty.mqttbroker.entity.EncryptedPayload;
import com.mo1ty.mqttbroker.entity.MqttMsgPayload;
import com.mo1ty.mqttbroker.entity.MessageStruct;
import com.mo1ty.mqttbroker.extensions.PublishExtensionMain;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;


public class MqttBroker {

    private static HashMap<String, X509Certificate> certificateHashMap = new HashMap<>();
    private static HashMap<String, KeyPair> privateKeyHashMap = new HashMap<>();
    private static HashMap<String, PublicKey> publicKeyHashMap = new HashMap<>();
    private static final CertVerify certVerify = new CertVerify();
    private static final KyberBroker kyberBroker = new KyberBroker();

    public static void main(String[] args){

        EmbeddedExtensionBuilder extensionBuilder = new EmbeddedExtensionBuilderImpl();
        EmbeddedExtension publishExtension = extensionBuilder
                .withId("pub_ext")
                .withName("Publish extension")
                .withVersion("1.0.0")
                .withExtensionMain(new PublishExtensionMain())
                .build();

        EmbeddedHiveMQBuilder hiveMqBuilder = new EmbeddedHiveMQBuilderImpl()
                .withEmbeddedExtension(
                        publishExtension
                );

        EmbeddedHiveMQ hiveMQ = hiveMqBuilder.build();



        CompletableFuture<Void> completableFuture = hiveMQ.start();
    }




}
