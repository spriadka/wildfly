package org.wildfly.test.integration.elytron.ssl;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpVersion;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.apache.mina.util.AvailablePortFinder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.Header;
import org.mockserver.model.HttpResponse;
import org.mockserver.model.NottableString;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.x500.GeneralName;
import org.wildfly.security.x500.cert.AccessDescription;
import org.wildfly.security.x500.cert.AuthorityInformationAccessExtension;
import org.wildfly.security.x500.cert.BasicConstraintsExtension;
import org.wildfly.security.x500.cert.ExtendedKeyUsageExtension;
import org.wildfly.security.x500.cert.SelfSignedX509CertificateAndSigningKey;
import org.wildfly.security.x500.cert.X509CertificateBuilder;
import org.xipki.datasource.DataSourceFactory;
import org.xipki.datasource.DataSourceWrapper;
import org.xipki.http.servlet.ServletURI;
import org.xipki.http.servlet.SslReverseProxyMode;
import org.xipki.ocsp.server.impl.HttpOcspServlet;
import org.xipki.ocsp.server.impl.OcspServer;
import org.xipki.security.SecurityFactoryImpl;
import org.xipki.security.SignerFactoryRegisterImpl;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.wildfly.security.x500.X500.OID_AD_OCSP;
import static org.wildfly.security.x500.X500.OID_KP_OCSP_SIGNING;

@RunWith(Arquillian.class)
@RunAsClient
public class UndertowSslCertificationRevocationOCSPTestCase {

    private static final int OCSP_SERVER_PORT = AvailablePortFinder.getNextAvailable();
    private static final char[] PASSWORD = "Elytron".toCharArray();
    private static final String CA_JKS_LOCATION = "./target/test-classes/ca/jks";
    private static final File CA_DIR = new File(CA_JKS_LOCATION);

    private static TestingOcspServer ocspServer;

    @BeforeClass
    public static void setUp() throws Exception {
        if (!CA_DIR.exists()) {
            CA_DIR.mkdirs();
        }
        setUpOcspResources();
        ocspServer = new TestingOcspServer(OCSP_SERVER_PORT);
        ocspServer.start();
    }

    private static void setUpOcspResources() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        Security.addProvider(new BouncyCastleProvider());
        X500Principal issuerDN = new X500Principal(
            "CN=Elytron CA, ST=Elytron, C=UK, EMAILADDRESS=elytron@wildfly.org, O=Root Certificate Authority");
        SelfSignedX509CertificateAndSigningKey issuerSelfSignedX509CertificateAndSigningKey = SelfSignedX509CertificateAndSigningKey.builder()
            .setDn(issuerDN)
            .setKeyAlgorithmName("RSA")
            .setSignatureAlgorithmName("SHA1withRSA")
            .addExtension(false, "BasicConstraints", "CA:true,pathlen:2147483647")
            .build();
        X509Certificate issuerCertificate = issuerSelfSignedX509CertificateAndSigningKey.getSelfSignedCertificate();
        KeyPair ocspResponderKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspResponderSigningKey = ocspResponderKeys.getPrivate();
        PublicKey ocspResponderPublicKey = ocspResponderKeys.getPublic();
        X509Certificate ocspResponderCertificate = new X509CertificateBuilder()
            .setIssuerDn(issuerDN)
            .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=OcspResponder"))
            .setSignatureAlgorithmName("SHA1withRSA")
            .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
            .setPublicKey(ocspResponderPublicKey)
            .setSerialNumber(new BigInteger("15"))
            .addExtension(new BasicConstraintsExtension(false, false, -1))
            .addExtension(new ExtendedKeyUsageExtension(false, Collections.singletonList(OID_KP_OCSP_SIGNING)))
            .build();
        KeyStore ocspResponderKeyStore = createKeyStore();
        ocspResponderKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspResponderKeyStore.setKeyEntry("ocspResponder", ocspResponderSigningKey, PASSWORD,
            new X509Certificate[] {ocspResponderCertificate, issuerCertificate});
        createTemporaryKeyStoreFile(ocspResponderKeyStore, new File(CA_DIR, "ocsp-responder.keystore"), PASSWORD);
        KeyPair ocspCheckedGoodKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspCheckedGoodSigningKey = ocspCheckedGoodKeys.getPrivate();
        PublicKey ocspCheckedGoodPublicKey = ocspCheckedGoodKeys.getPublic();

        X509Certificate ocspCheckedGoodCertificate = new X509CertificateBuilder()
            .setIssuerDn(issuerDN)
            .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedGood"))
            .setSignatureAlgorithmName("SHA1withRSA")
            .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
            .setPublicKey(ocspCheckedGoodPublicKey)
            .setSerialNumber(new BigInteger("16"))
            .addExtension(new BasicConstraintsExtension(false, false, -1))
            .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_SERVER_PORT + "/ocsp"))
            )))
            .build();
        KeyStore ocspCheckedGoodKeyStore = createKeyStore();
        ocspCheckedGoodKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspCheckedGoodKeyStore.setKeyEntry("checked", ocspCheckedGoodSigningKey, PASSWORD, new X509Certificate[]{ocspCheckedGoodCertificate,issuerCertificate});
        createTemporaryKeyStoreFile(ocspCheckedGoodKeyStore, new File(CA_DIR, "ocsp-checked-good.keystore"), PASSWORD);

        // Generates REVOKED certificate referencing the OCSP responder
        KeyPair ocspCheckedRevokedKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspCheckedRevokedSigningKey = ocspCheckedRevokedKeys.getPrivate();
        PublicKey ocspCheckedRevokedPublicKey = ocspCheckedRevokedKeys.getPublic();

        X509Certificate ocspCheckedRevokedCertificate = new X509CertificateBuilder()
            .setIssuerDn(issuerDN)
            .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedRevoked"))
            .setSignatureAlgorithmName("SHA1withRSA")
            .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
            .setPublicKey(ocspCheckedRevokedPublicKey)
            .setSerialNumber(new BigInteger("17"))
            .addExtension(new BasicConstraintsExtension(false, false, -1))
            .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_SERVER_PORT + "/ocsp"))
            )))
            .build();
        KeyStore ocspCheckedRevokedKeyStore = createKeyStore();
        ocspCheckedRevokedKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspCheckedRevokedKeyStore.setKeyEntry("checked", ocspCheckedRevokedSigningKey, PASSWORD, new X509Certificate[]{ocspCheckedRevokedCertificate,issuerCertificate});
        createTemporaryKeyStoreFile(ocspCheckedRevokedKeyStore, new File("ocsp-checked-revoked.keystore"), PASSWORD);

        // Generates UNKNOWN certificate referencing the OCSP responder
        KeyPair ocspCheckedUnknownKeys = keyPairGenerator.generateKeyPair();
        PrivateKey ocspCheckedUnknownSigningKey = ocspCheckedUnknownKeys.getPrivate();
        PublicKey ocspCheckedUnknownPublicKey = ocspCheckedUnknownKeys.getPublic();

        X509Certificate ocspCheckedUnknownCertificate = new X509CertificateBuilder()
            .setIssuerDn(issuerDN)
            .setSubjectDn(new X500Principal("OU=Elytron, O=Elytron, C=UK, ST=Elytron, CN=ocspCheckedUnknown"))
            .setSignatureAlgorithmName("SHA1withRSA")
            .setSigningKey(issuerSelfSignedX509CertificateAndSigningKey.getSigningKey())
            .setPublicKey(ocspCheckedUnknownPublicKey)
            .setSerialNumber(new BigInteger("18"))
            .addExtension(new BasicConstraintsExtension(false, false, -1))
            .addExtension(new AuthorityInformationAccessExtension(Collections.singletonList(
                new AccessDescription(OID_AD_OCSP, new GeneralName.URIName("http://localhost:" + OCSP_SERVER_PORT + "/ocsp"))
            )))
            .build();
        KeyStore ocspCheckedUnknownKeyStore = createKeyStore();
        ocspCheckedUnknownKeyStore.setCertificateEntry("ca", issuerCertificate);
        ocspCheckedUnknownKeyStore.setKeyEntry("checked", ocspCheckedUnknownSigningKey, PASSWORD, new X509Certificate[]{ocspCheckedUnknownCertificate,issuerCertificate});
        createTemporaryKeyStoreFile(ocspCheckedUnknownKeyStore, new File(CA_DIR, "ocsp-checked-unknown.keystore"), PASSWORD);
    }

    private static KeyStore createKeyStore()
        throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(null,null);
        return ks;
    }

    private static void createTemporaryKeyStoreFile(KeyStore keyStore, File outputFile, char[] password) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(outputFile)){
            keyStore.store(fos, password);
        }
    }

    @AfterClass
    public static void tearDown() throws SQLException {
        ocspServer.stop();
    }

    static class TestingOcspServer {
        private int port;
        private OcspServer ocspServer = null;
        private ClientAndServer server;
        private Connection connection;
        private SecurityFactoryImpl securityFactory = new SecurityFactoryImpl();

        public TestingOcspServer(int port) throws Exception {
            this.port = port;
            initDatabase();
        }

        private void initDatabase() throws Exception {
            DataSourceFactory dataSourceFactory = new DataSourceFactory();
            DataSourceWrapper dataSourceWrapper = dataSourceFactory.createDataSource("datasource1",
                TestingOcspServer.class.getResource("ocsp-db.properties").openStream(),
                securityFactory.getPasswordResolver());
            connection = dataSourceWrapper.getConnection();

            // structure described in:
            // https://github.com/xipki/xipki/blob/v3.0.0/ca-server/src/main/resources/sql/ocsp-init.xml

            connection.prepareStatement("CREATE TABLE ISSUER (\n"
                + "    ID INT NOT NULL,\n"
                + "    SUBJECT VARCHAR(350) NOT NULL,\n"
                + "    NBEFORE BIGINT NOT NULL,\n" // notBefore
                + "    NAFTER BIGINT NOT NULL,\n" // notAfter
                + "    S1C CHAR(28) NOT NULL,\n" // base64 encoded SHA1 sum of the certificate
                + "    REV SMALLINT DEFAULT 0,\n" // whether the certificate is revoked
                + "    RR SMALLINT,\n" // revocation reason
                + "    RT BIGINT,\n" // revocation time
                + "    RIT BIGINT,\n" // revocation invalidity time
                + "    CERT VARCHAR(4000) NOT NULL,\n"
                + "    CRL_INFO VARCHAR(1000)\n" // CRL information if this issuer is imported from a CRL
                + ");").execute();

            connection.prepareStatement("CREATE TABLE CERT (\n"
                + "    ID BIGINT NOT NULL,\n"
                + "    IID INT NOT NULL,\n" // issuer id (reference into ISSUER table)
                + "    SN VARCHAR(40) NOT NULL,\n" // serial number
                + "    LUPDATE BIGINT NOT NULL,\n" // last update
                + "    NBEFORE BIGINT,\n" // notBefore
                + "    NAFTER BIGINT,\n" // notAfter
                + "    REV SMALLINT DEFAULT 0,\n" // whether the certificate is revoked
                + "    RR SMALLINT,\n" // revocation reason
                + "    RT BIGINT,\n" // revocation time
                + "    RIT BIGINT,\n" // revocation invalidity time
                + "    PN VARCHAR(45)\n" // certificate profile name
                + ");").execute();
        }

        public void start() throws Exception {
            Assert.assertNull("OCSP server already started", ocspServer);

            ocspServer = new OcspServer();
            ocspServer.setConfFile(TestingOcspServer.class.getResource("ocsp-responder.xml").getFile());

            securityFactory.setSignerFactoryRegister(new SignerFactoryRegisterImpl());
            ocspServer.setSecurityFactory(securityFactory);

            ocspServer.init();
            HttpOcspServlet servlet = new HttpOcspServlet();
            servlet.setServer(ocspServer);

            server = new ClientAndServer(port);
            server.when(
                request()
                    .withMethod("POST")
                    .withPath("/ocsp"),
                Times.unlimited())
                .callback(request -> {
                    ByteBuf buffer = Unpooled.wrappedBuffer(request.getBody().getRawBytes());
                    FullHttpRequest
                        nettyRequest = new DefaultFullHttpRequest(
                        HttpVersion.HTTP_1_0, HttpMethod.POST, request.getPath().getValue(), buffer);
                    for (Header header : request.getHeaderList()) {
                        for (NottableString value : header.getValues()) {
                            nettyRequest.headers().add(header.getName().getValue(), value.getValue());
                        }
                    }

                    FullHttpResponse nettyResponse;
                    try {
                        nettyResponse = servlet.service(nettyRequest, new ServletURI(request.getPath().getValue()), null,
                            SslReverseProxyMode.NONE);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    HttpResponse response = response()
                        .withStatusCode(nettyResponse.status().code())
                        .withBody(nettyResponse.content().array());

                    for (Map.Entry<String, String> header : nettyResponse.headers()) {
                        response.withHeader(header.getKey(), header.getValue());
                    }

                    return response;
                });
        }

        public void stop() throws SQLException {
            Assert.assertNotNull("OCSP server not started", ocspServer);
            server.stop();
            ocspServer.shutdown();
            connection.close();
            ocspServer = null;
        }

        public void createIssuer(int id, X509Certificate issuer) throws SQLException, CertificateException,
            NoSuchAlgorithmException {
            Assert.assertNull("OCSP server already started", ocspServer);

            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO ISSUER (ID, SUBJECT, NBEFORE, NAFTER, S1C, CERT) VALUES (?, ?, ?, ?, ?, ?)");
            statement.setInt(1, id);
            statement.setString(2, issuer.getSubjectDN().toString());
            statement.setLong(3, issuer.getNotBefore().toInstant().getEpochSecond());
            statement.setLong(4, issuer.getNotAfter().toInstant().getEpochSecond());
            statement.setString(5,
                ByteIterator.ofBytes(digest.digest(issuer.getEncoded())).base64Encode().drainToString());
            statement.setString(6, ByteIterator.ofBytes(issuer.getEncoded()).base64Encode().drainToString());
            statement.execute();
        }

        public void createCertificate(int id, int issuerId, X509Certificate certificate) throws SQLException {
            long time = Instant.now().getEpochSecond();
            PreparedStatement statement = connection.prepareStatement(
                "INSERT INTO CERT (ID, IID, SN, LUPDATE, NBEFORE, NAFTER) VALUES (?, ?, ?, ?, ?, ?)");
            statement.setInt(1, id);
            statement.setInt(2, issuerId);
            statement.setString(3, certificate.getSerialNumber().toString(16));
            statement.setLong(4, time);
            statement.setLong(5, certificate.getNotBefore().toInstant().getEpochSecond());
            statement.setLong(6, certificate.getNotAfter().toInstant().getEpochSecond());
            statement.execute();
        }

        public void revokeCertificate(int id, int reason) throws SQLException {
            long time = Instant.now().getEpochSecond();
            PreparedStatement statement =
                connection.prepareStatement("UPDATE CERT SET REV = 1, RR = ?, RT = ?, RIT = ? WHERE ID = ?");
            statement.setInt(1, reason);
            statement.setLong(2, time);
            statement.setLong(3, time);
            statement.setInt(4, id);
            statement.execute();
        }
    }

    @Test
    public void test() {
        System.out.println("WOOP WOOP");
        Assert.fail("Not implemented yet");
    }
}
