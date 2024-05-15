package com.mo1ty.mqttbroker;

import com.hivemq.embedded.EmbeddedExtension;
import com.hivemq.embedded.EmbeddedExtensionBuilder;
import com.hivemq.embedded.EmbeddedHiveMQ;
import com.hivemq.embedded.EmbeddedHiveMQBuilder;
import com.hivemq.embedded.internal.EmbeddedExtensionBuilderImpl;
import com.hivemq.embedded.internal.EmbeddedHiveMQBuilderImpl;
import com.mo1ty.mqttbroker.extensions.PublishExtensionMain;
import java.util.concurrent.CompletableFuture;


public class MqttBroker {

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
