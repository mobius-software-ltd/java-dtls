# Nonblocking Dtls Client and server based on Bouncy Castle

This library implements nonblocking dtls client for java. It may be used with netty and without netty library 

## Features

* **Non blocking**

* **Allows custom handling for each handshake message**

* **Implements netty handler.** 

## Getting Started

* To implement based on netty library please see tests. Just remove Message Handler interface, Replace Dummy Handler with real one, and in case required add custom handling for handshake started , handshake ended and error occured events. If you would like to implement custom handling for handshake messaging ( for example for certificate validation ) please replace Test Handshake Handler with new implementation. If you dont need custom handling just remove it usage (pass null instead of handler) 
* To implement without netty library create new instance of AsyncDtlsClientProtocol/AsyncDtlsServer protocol ,and send/receive packets with it.
* In both cases replace the certificates with real ones. 

## [License](LICENSE.md)
