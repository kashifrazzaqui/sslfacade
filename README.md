sslfacade
=========

### Overview

An attempt to make the use of Java's SSLEngine easier, the SSLFacade provides an integrated, hopefully simple, api to interact with the Java SSLEngine.

The facade has two important listeners. The first for informing the host application of handshake completion and the other for emitting ciphered and plain data.

The SSLFacade consumes cipher data via the SSLFacade.decrypt() call and emits the result, if any, through SSLListener.onPlaindata(). Similarly, any data you want to send to your SSL peer must first be converted to cipher via the encrypt() call and the result is emitted via SSLListener.onWrappedData()

The SSLEngine also generates some long running tasks during the handshake process these tasks should be handled by the host application through an implementation of ITaskHandler. A default implementation which executes the tasks on the same thread is provided as prj.sslfacade.DefaultTaskHandler. You may want to write your own if you wish to execute these tasks in a separate thread - please refer the default implementation when you do so.


##### Construction

```java
        ISSLFacade ssl = new SSLFacade(_sslContext, false, false, _taskHandler);
```

SSLFacade's constructor takes four inputs

1. A Java SSLContext
2. A boolean indicating whether the SSL is to act like a client or server
3. A boolean indicating if client needs to be authenticated - only useful when operating as a server.
4. A ITaskHandler implementation to handle long running tasks

##### Setup listeners

Attach a handshake completion listener

```java
    
        
        ssl.setHandshakeCompletedListener(new IHandshakeCompletedListener(){
        
         @Override
            public void onComplete()
            {
                //Called when the ssl handshake is completed
            }
        });
        
```

Attach a SSLListener for getting results form encrypt/decrypt calls

```java

        ssl.setSSLListener(new ISSLListener()
        {
            @Override
            public void onWrappedData(ByteBuffer wrappedBytes)
            {
               //Send these bytes via your host application's transport
            }

            @Override
            public void onPlainData(ByteBuffer plainBytes)
            {
                //This is the deciphered payload for your app to consume   
            }
        });
        
         
        ssl.beginHandshake();
        
```

##### Receiving

Once you have begun the handshake any data you receive on your transport needs to be fed to the ssl engine as such.

```java
ssl.decrypt(incomingPayload);
```
During the handshake no data will be emitted via the SSLListener.onPlainData method. But data which is to be sent to the peer for purposes of handshake will be emitted via the SSLListener.onWrappedData method. These bytes should be sent to the SSL peer by the host application.

After the handshake, if you receive any data and pass it to ssl.decrypt() you will get decrypted plain data via the SSLListener.onPlainData() method if the bytes you passed contain a full TLS record. If not, they will be cached for you and as you pass in the remaining data the equivalent plain text will be emitted. The host application just needs to call decrypt() on all incoming payload and wait for plain data on listeners with no additional management involved.

##### Sending

If there is any data you wish to send you must encrypt it first as such.

```java
ssl.encrypt(data)
```
The result of this encryption will be available through SSLListener.onWrappedData()

##### Closing

To close a SSL connection and send an SSL finish message use close()

```java
ssl.close()
```

To close a SSL connection without sending a SSL finish message or if transport is no longer available

```java
ssl.terminate()
```

##### Not supported

* SSL session resumption
* Renegotiaion of handshake on an already existing session.
* Multi-buffer scatter-gather wrap and unwrap operations.
* Client certificate authentication requested (not the same as required, which is supported)


If you have suggestions/requests, generate a pull request or drop me a message.

*Note that this code has been tested and used but the test is not in this source tree, I will at somepoint include the tests here*

[![githalytics.com alpha](https://cruel-carlota.pagodabox.com/721d6f60a885788cfe268ae13d7c991e "githalytics.com")](http://githalytics.com/kashifrazzaqui/sslfacade)
