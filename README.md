# pqc-mqtt-broker

Post-quantum MQTT broker - an MQTT broker application based on embedded HiveMQ Community Edition, using Bouncy Castle for communication.
Requires clients for communication. For example, pqc-mqtt contains compatible publisher and subscriber implementations.

## How to launch
Broker application requires Java 11 to work. Before start, it is possible to set algorithm used in certificate verification on the field "certVerify" in PublishExtensionMain file. By default it is Falcon.

build.gradle file contains "mqttBroker" task that can be used to build a fatJar archive. 

## Shortly about security
This application is capable of communication on two levels of security: 
1) First level utilizes message signatures. Broker will validate them before sending to the subscribers. Algorithms supported are Falcon and Dilithium. (only one is usable at time) 
2) Second level requires handshake for clients to properly. Without the handshake, it is not possible to receive AES keys and therefore broker will block any packet before handshake is complete.
