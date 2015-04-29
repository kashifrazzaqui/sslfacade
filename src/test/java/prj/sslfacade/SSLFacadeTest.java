package prj.sslfacade;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Semaphore;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManagerFactory;
import org.assertj.core.api.Assertions;
import org.junit.Before;
import org.junit.Test;

/**
 * This test check if the communication over the SSLFacade works. Actually it was written in the first place more likely to check the library.
 */
public class SSLFacadeTest {

  public static final String SERVER_TAG = "server";
  public static final String CLIENT_TAG = "client";

  public static final String JKS_FILE_PASSWORD = "123456";
  public static final String JKS_FILE = "src/test/resources/test.jks";

  public static final String END_OF_SESSION = "END_OF_SESSION";
  public static final String END_OF_HANDSHAKE = "END_OF_HANDSHAKE";
  public static final String HELLO_FROM_CLIENT_1 = "Hello from client 1";
  public static final String HELLO_FROM_SERVER_1 = "Hello from server 1";
  public static final String HELLO_FROM_CLIENT_2 = "Hello from client 2";
  public static final String HELLO_FROM_SERVER_2 = "Hello from server 2";

  private final ITaskHandler taskHandler = new DefaultTaskHandler();

  private final CharsetEncoder encoder = Charset.forName("US-ASCII").newEncoder();
  private final CharsetDecoder decoder = Charset.forName("US-ASCII").newDecoder();

  private final CharBuffer cleintIn1 = CharBuffer.wrap(HELLO_FROM_CLIENT_1);
  private final CharBuffer serverIn1 = CharBuffer.wrap(HELLO_FROM_SERVER_1);
  private final CharBuffer cleintIn2 = CharBuffer.wrap(HELLO_FROM_CLIENT_2);
  private final CharBuffer serverIn2 = CharBuffer.wrap(HELLO_FROM_SERVER_2);

  private SSLContext sslCtx;

  public SSLFacadeTest() {
  }

  private static void log(final String message) {
    System.out.println("[SSLFacadeTest]: " + message);
  }

  public ISSLFacade createSSL(final String who, boolean client, final List<String> notifications, final Semaphore sem) {
    ISSLFacade ssl = new SSLFacade(sslCtx, client, false, taskHandler);
    attachHandshakeListener(who, ssl, notifications, sem);

    return ssl;
  }

  public void attachHandshakeListener(final String who, final ISSLFacade ssl, final List<String> notifications, final Semaphore sem) {
    ssl.setHandshakeCompletedListener(new IHandshakeCompletedListener() {
      @Override
      public void onComplete() {
        log(who + ": Handshake completed.");
        notifications.add(END_OF_HANDSHAKE);
        sem.release();
      }
    });
  }

  public ISSLListener crateListener(final String who, final ISSLFacade sslServer, final List<String> notificatons, final Semaphore sem) {
    return new ISSLListener() {
      @Override
      public void onWrappedData(ByteBuffer wrappedBytes) {
        try {
          log(who + ": pass data " + wrappedBytes);
          sslServer.decrypt(wrappedBytes);
          log(who + ": data decrypted " + wrappedBytes);
        } catch (SSLException ex) {
          log(who + ": Error while sending data to peer;" + ex);
        }
      }

      @Override
      public void onPlainData(ByteBuffer plainBytes) {
        log(who + ": received plain data: " + plainBytes);
        try {
          CharBuffer decodedString = decoder.decode(plainBytes);
          log(who + ": String received: " + decodedString);
          notificatons.add(decodedString.toString());
          sem.release();
        } catch (CharacterCodingException ex) {
          log(who + ": !ERROR! could not decode data received from peer");
        }
      }
    };
  }

  private void attachSessionCloseListener(final String who, final ISSLFacade sslServer, final List<String> notifications, final Semaphore sem) {
    sslServer.setCloseListener(new ISessionClosedListener() {
      public void onSessionClosed() {
        log(who + ": peer closed the session. Post notification on sem : " + sem);
        notifications.add(END_OF_SESSION);
        sem.release();
        log(who + ": peer closed the session. Sem notified : " + sem);
      }
    });
  }

  @Before
  public void setUp() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, UnrecoverableKeyException, KeyManagementException {
    KeyStore ks = KeyStore.getInstance("JKS");
    KeyStore ts = KeyStore.getInstance("JKS");
    String keyStoreFile = JKS_FILE;
    String trustStoreFile = JKS_FILE;
    String passw = JKS_FILE_PASSWORD;

    char[] passphrase = passw.toCharArray();

    ks.load(new FileInputStream(keyStoreFile), passphrase);

    ts.load(new FileInputStream(trustStoreFile), passphrase);

    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks, passphrase);

    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    tmf.init(ts);

    sslCtx = SSLContext.getInstance("TLS");
    sslCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
  }

  /**
   * @throws javax.net.ssl.SSLException
   * @throws java.nio.charset.CharacterCodingException
   * @throws java.lang.InterruptedException
   */
  @Test
  public void check_simpleCommunicationScenario() throws SSLException, CharacterCodingException, InterruptedException, IOException {
    // given
    List<String> clientNotifications = new LinkedList<String>();
    List<String> serverNotifications = new LinkedList<String>();

    final Semaphore sslClientSem = new Semaphore(0);
    final Semaphore sslServerSem = new Semaphore(0);

    final ISSLFacade sslClient = createSSL(CLIENT_TAG, false, clientNotifications, sslClientSem);
    final ISSLFacade sslServer = createSSL(SERVER_TAG, true, serverNotifications, sslServerSem);

    log("== Init SSL listeners");
    sslClient.setSSLListener(crateListener(CLIENT_TAG, sslServer, clientNotifications, sslClientSem));
    sslServer.setSSLListener(crateListener(SERVER_TAG, sslClient, serverNotifications, sslServerSem));

    log("== Start handshake handlers");
    // when
    sslClient.beginHandshake();
    sslServer.beginHandshake();

    log("== Client waits untill handshake is done");
    sslClientSem.acquire();

    //* AK: I'm not sure if this is OK that the handshake is not notified on the Server part.
    //* This must be double checked.
    //
    //  sslServerSem.acquire();
    log("== Sending first message (full duplex)");
    sslClient.encrypt(encoder.encode(cleintIn1));
    sslServer.encrypt(encoder.encode(serverIn1));

    log("== Wait untill the first message arrived");
    sslClientSem.acquire();
    sslServerSem.acquire();

    log("== Sending second message to server");
    sslClient.encrypt(encoder.encode(cleintIn2));
    sslServerSem.acquire();

    log("== Sending second message to client");
    sslServer.encrypt(encoder.encode(serverIn2));
    sslClientSem.acquire();

    log("== Close connection on client side");
    attachSessionCloseListener(CLIENT_TAG, sslClient, clientNotifications, sslClientSem);
    attachSessionCloseListener(SERVER_TAG, sslServer, serverNotifications, sslServerSem);
    sslClient.close();

    log("== Wait server has received end of session on sem " + sslClientSem);
    sslServerSem.acquire();

    //then
    Assertions.assertThat(clientNotifications)
            .hasSize(3)
            .containsExactly(END_OF_HANDSHAKE, HELLO_FROM_SERVER_1, HELLO_FROM_SERVER_2);

    Assertions.assertThat(serverNotifications)
            .hasSize(3)
            .containsExactly(HELLO_FROM_CLIENT_1, HELLO_FROM_CLIENT_2, END_OF_SESSION);
  }

  @Test
  public void check_clientModeSet() {
    // given
    boolean isClient = true;
    
    //when
    ISSLFacade fascade = new SSLFacade(sslCtx, isClient, false, taskHandler);
    
    //then
    Assertions.assertThat(fascade.isClientMode());
  }
  
  @Test
  public void check_serverModeSet() {
    // given
    boolean isClient = true;
    
    //when
    ISSLFacade fascade = new SSLFacade(sslCtx, isClient, false, taskHandler);
    
    //then
    Assertions.assertThat(fascade.isClientMode());
  }
}
