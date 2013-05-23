package old;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class SSLManager<KEY>
{
    private final boolean _clientMode;
    private SSLContext _sslContext;
    private SSLTransport<KEY> _transport;
    private final Map<KEY, SSLEngine> _sslEngines;
    private final Map<KEY, HandshakeCompletedListener> _handshakeCompletedListeners;
    private final Map<KEY, byte[]> _remainingData;
    private final Map<KEY, Boolean> _handshakeCompletedStatus;

    public SSLManager(boolean clientMode) throws IOException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, CertificateException, UnrecoverableKeyException
    {
        _sslEngines = new HashMap<>();
        _remainingData = new HashMap<>();
        _handshakeCompletedStatus = new HashMap<>();
        _handshakeCompletedListeners = new HashMap<>();
        _clientMode = clientMode;
        _sslContext = getSSLContext();
    }

    void prepare(KEY userKey)
    {
        SSLEngine sslEngine = _sslContext.createSSLEngine();
        sslEngine.setUseClientMode(_clientMode);
        sslEngine.setNeedClientAuth(false);
        _sslEngines.put(userKey, sslEngine);
        _remainingData.put(userKey, new byte[0]);
        _handshakeCompletedStatus.put(userKey, false);
    }

    static SSLContext getSSLContext() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException, UnrecoverableKeyException
    {
        String password = "android@39";
        char[] passphrase = password.toCharArray();
        // First initialize the key and trust material.
        String keystore = "android-ssc.jks";
        KeyStore ks = KeyStore.getInstance("JKS");
        FileInputStream stream = new FileInputStream(keystore);
        ks.load(stream, passphrase);
        stream.close();
        SSLContext sslContext = SSLContext.getInstance("TLS");

        // TrustManager's decide whether to allow connections.
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        // KeyManager's decide which key material to use.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, passphrase);
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return sslContext;
    }

    void beginSSLHandshake(KEY userKey, HandshakeCompletedListener handshakeCompletedListener) throws IOException
    {
        _handshakeCompletedListeners.put(userKey, handshakeCompletedListener);
        SSLEngine sslEngine = _sslEngines.get(userKey);
        sslEngine.beginHandshake();
        shakehands(userKey);
    }

    void shakehands(KEY userKey) throws IOException
    {
        SSLEngine sslEngine = _sslEngines.get(userKey);
        while (true)
        {
            SSLEngineResult.HandshakeStatus handshakeStatus = sslEngine.getHandshakeStatus();
            switch (handshakeStatus)
            {
                case FINISHED:
                    finishHandshake(userKey);
                    return;
                case NOT_HANDSHAKING:
                    return;
                case NEED_TASK:
                    processLongRunningTask(sslEngine);
                    break;
                case NEED_WRAP:
                    SSLEngineResult result = wrapAndSend(userKey);
                    if (isHandshakeStatusFinished(result))
                    {
                        finishHandshake(userKey);
                        return;
                    }
                    break;
                case NEED_UNWRAP:
                    if (anyUnprocessedDataFromPreviousReceives(userKey))
                    {
                        ByteBuffer decryptedData = allocateDecryptionBufferForReceiving(userKey);
                        SSLEngineResult unwrapResult = decrypt(userKey, new byte[0], decryptedData);
                        if (unwrapResult.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP))
                        {
                            return;
                        }
                        else if (isHandshakeStatusFinished(unwrapResult))
                        {
                            finishHandshake(userKey);
                            return;
                        }
                        else
                        {
                            break;
                        }
                    }
                    return;
            }
        }
    }

    private boolean anyUnprocessedDataFromPreviousReceives(KEY userKey)
    {
        return _remainingData.get(userKey).length > 0;
    }

    private static boolean isHandshakeStatusFinished(SSLEngineResult result)
    {
        return result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.FINISHED);
    }

    private SSLEngineResult wrapAndSend(KEY userKey) throws IOException
    {
        ByteBuffer encryptedData = allocateEncryptedByteBufferForSending(userKey);
        SSLEngineResult result = encrypt(userKey, new byte[0], encryptedData);
        encryptedData.flip();

        byte[] sslMessage = getSSLMessageBytesFromBuffer(encryptedData, result);
        _transport.send(userKey, sslMessage);
        return result;
    }

    private static byte[] getSSLMessageBytesFromBuffer(ByteBuffer encryptedData, SSLEngineResult result)
    {
        byte[] sslMessage = new byte[result.bytesProduced()];
        encryptedData.get(sslMessage, 0, result.bytesProduced());
        return sslMessage;
    }

    void finishHandshake(KEY userKey)
    {
        _handshakeCompletedStatus.put(userKey, true);
        _handshakeCompletedListeners.get(userKey).handshakeCompleted(null);
        _handshakeCompletedListeners.remove(userKey);
    }

    static void processLongRunningTask(SSLEngine sslEngine)
    {
        Runnable task;
        while ((task = sslEngine.getDelegatedTask()) != null)
        {
            task.run();
        }
    }

    SSLEngineResult decrypt(KEY userKey, byte[] incomingBytes, ByteBuffer decryptedData) throws SSLException
    {
        ByteBuffer encryptedData = getDataForDecryption(userKey, incomingBytes);
        try
        {
            SSLEngineResult result = unwrap(userKey, decryptedData, encryptedData);
            storeUnprocessedData(userKey, encryptedData);
            if (isHandshakeStatusFinished(result))
            {
                finishHandshake(userKey);
            }
            return result;
        }
        catch (SSLException exception)
        {
            throw exception;
        }
    }

    private ByteBuffer getDataForDecryption(KEY userKey, byte[] encryptedData)
    {
        byte[] remainingData = _remainingData.get(userKey);
        int length_remainingData = remainingData.length;
        int length_encryptedData = encryptedData.length;
        ByteBuffer totalIncomingData = ByteBuffer.allocate(length_remainingData + length_encryptedData);

        addPendingData(userKey, remainingData, totalIncomingData);
        addLatestData(encryptedData, totalIncomingData);

        totalIncomingData.flip();
        return totalIncomingData;
    }


    private void storeUnprocessedData(KEY userKey, ByteBuffer totalIncomingData)
    {
        byte[] remainingData = Arrays.copyOfRange(totalIncomingData.array(), totalIncomingData.position(), totalIncomingData.limit());
        _remainingData.put(userKey, remainingData);
    }

    private SSLEngineResult unwrap(KEY key, ByteBuffer unwrappedData, ByteBuffer totalIncomingData) throws SSLException
    {
        SSLEngine sslEngine = _sslEngines.get(key);
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        int totalBytesToBeConsumed = totalIncomingData.array().length;
        do
        {
            result = sslEngine.unwrap(totalIncomingData, unwrappedData);
            totalBytesConsumed = totalBytesConsumed + result.bytesConsumed();
        }
        while (needsUnwrap(key, result, totalBytesConsumed, totalBytesToBeConsumed));
        return result;
    }

    private boolean needsUnwrap(KEY key, SSLEngineResult result, int totalBytesConsumed, int totalBytesToBeConsumed)
    {
        if (!isHandshakeCompleted(key))
        {
            return result.getStatus() == SSLEngineResult.Status.OK && result.getHandshakeStatus().equals(SSLEngineResult.HandshakeStatus.NEED_UNWRAP) && result.bytesProduced() == 0;
        }
        else
        {
            return result.getStatus() == SSLEngineResult.Status.OK && (result.bytesProduced() != 0 || totalBytesConsumed < totalBytesToBeConsumed);
        }
    }

    public ByteBuffer allocateDecryptionBufferForReceiving(KEY userKey)
    {
        try
        {
            SSLEngine sslEngine = _sslEngines.get(userKey);
            SSLSession session = sslEngine.getSession();
            int applicationBufferSize = session.getApplicationBufferSize();
            return ByteBuffer.allocate(applicationBufferSize);
        }
        catch (NullPointerException exception)
        {
            // The socket may have been closed and hence trying to get the session
            // from the ssl engine will return a null. This could be a pretty common occurrence
            return null;
        }
    }

    private static void addLatestData(byte[] encryptedData, ByteBuffer totalIncomingData)
    {
        if (encryptedData.length > 0)
        {
            totalIncomingData.put(encryptedData);
        }
    }

    private void addPendingData(KEY userKey, byte[] remainingData, ByteBuffer totalIncomingData)
    {
        if (remainingData.length > 0)
        {
            totalIncomingData.put(remainingData);
            _remainingData.put(userKey, new byte[0]);
        }
    }

    public boolean isHandshakeCompleted(KEY userKey)
    {
        return _handshakeCompletedStatus.get(userKey);
    }

    public SSLEngineResult encrypt(KEY userKey, byte[] data, ByteBuffer outgoingData) throws IOException
    {
        ByteBuffer applicationData = ByteBuffer.wrap(data);
        SSLEngine sslEngine = _sslEngines.get(userKey);
        return sslEngine.wrap(applicationData, outgoingData);
    }


    public void send(KEY userKey, byte[] plainBytes) throws IOException
    {
        ByteBuffer encryptedData = allocateEncryptedByteBufferForSending(userKey);
        SSLEngineResult result;
        int totalBytesConsumed = 0;
        do
        {
            result = encrypt(userKey, Arrays.copyOfRange(plainBytes, totalBytesConsumed, plainBytes.length), encryptedData);
            byte[] sendableData = copyToByteArray(encryptedData, result.bytesProduced());
            _transport.send(userKey, sendableData);
            encryptedData.clear();
            totalBytesConsumed += result.bytesConsumed();
        }
        while (result.getStatus().equals(SSLEngineResult.Status.OK) && totalBytesConsumed < plainBytes.length && result.bytesProduced() > 0);
    }

    public ByteBuffer allocateEncryptedByteBufferForSending(KEY userKey)
    {
        SSLEngine sslEngine = _sslEngines.get(userKey);
        int packetBufferSize = sslEngine.getSession().getPacketBufferSize();
        return ByteBuffer.allocate(packetBufferSize);
    }

    public void closeEngine(KEY userKey)
    {
        SSLEngine engine = _sslEngines.get(userKey);
        if (engine != null)
        {
            engine.closeOutbound();
            try
            {
                engine.closeInbound();
            }
            catch (SSLException ignored)
            {
            }
        }
        cleanState(userKey);
    }

    private void cleanState(KEY userKey)
    {
        _sslEngines.remove(userKey);
        _handshakeCompletedListeners.remove(userKey);
        _remainingData.remove(userKey);
        _handshakeCompletedStatus.remove(userKey);
    }

    public void setTransport(SSLTransport<KEY> sslTransport)
    {
        _transport = sslTransport;
    }

    private static byte[] copyToByteArray(ByteBuffer outgoingData, int size)
    {
        outgoingData.flip();
        byte[] bytes = new byte[size];
        outgoingData.get(bytes, 0, size);
        return bytes;
    }

}