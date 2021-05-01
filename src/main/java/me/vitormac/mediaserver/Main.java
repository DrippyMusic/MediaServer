package me.vitormac.mediaserver;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.cdimascio.dotenv.Dotenv;
import me.vitormac.mediacore.MediaProvider;
import me.vitormac.mediacore.data.Range;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.UUID;
import java.util.concurrent.Executors;

public class Main {

    private static final int PORT;
    private static final String ORIGIN;

    private static final Dotenv ENV = Dotenv.configure().ignoreIfMissing().load();

    static {
        EnvUtils.check(ENV, "PUBLIC_KEY");
        EnvUtils.check(ENV, "PRIVATE_KEY");

        PORT = Integer.parseInt(ENV.get("PORT", "4770"));
        ORIGIN = ENV.get("ORIGIN", "*");
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = createServer();
        server.setExecutor(Executors.newCachedThreadPool());

        RSAUtils rsa = new RSAUtils(ENV.get("PUBLIC_KEY"), ENV.get("PRIVATE_KEY"));

        server.createContext("/", (HttpExchange e) -> {
            try {
                String path = e.getRequestURI().getPath().substring(1);
                String data = rsa.decrypt(path);

                if (StringUtils.isEmpty(data)) {
                    throw new ClientException("Stream token not valid");
                }

                JsonObject object = JsonParser.parseString(data)
                        .getAsJsonObject();

                String name = object.get("id").getAsString();
                MediaProvider provider = MediaProvider.create(name);
                MediaProvider.MediaInfo info = provider.transform(object);

                Range range = Range.from(e.getRequestHeaders().getFirst("Range"));
                try (BufferedOutputStream output = IOUtils.buffer(e.getResponseBody());
                     BufferedInputStream stream = IOUtils.buffer(provider.stream(info, range))) {
                    e.getResponseHeaders().set("Accept-Ranges", "bytes");
                    e.getResponseHeaders().set("Content-Type", info.getType());
                    e.getResponseHeaders().set("Access-Control-Allow-Origin", ORIGIN);

                    Range content = info.getRange();
                    e.getResponseHeaders().set("Content-Range", content.toString());
                    e.sendResponseHeaders(206, content.getLength());

                    IOUtils.copy(stream, output);
                }
            } catch (ClientException | IllegalArgumentException exception) {
                int status = 400;

                if (exception instanceof ClientException) {
                    status = ((ClientException) exception).getStatus();
                }

                String message = exception.getMessage();
                e.sendResponseHeaders(status, message.length());

                try (BufferedOutputStream output = IOUtils.buffer(e.getResponseBody())) {
                    output.write(message.getBytes());
                }
            }
        });

        server.start();

        System.out.printf("Server running at [:%d]%n", PORT);
    }

    private static HttpServer createServer() throws Exception {
        InetSocketAddress address = new InetSocketAddress(PORT);

        if (PORT == 443) {
            EnvUtils.check(ENV, "CERT_PUBLIC");
            EnvUtils.check(ENV, "CERT_PRIVATE");

            char[] uuid = UUID.randomUUID().toString().toCharArray();
            KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
            store.load(null, uuid);

            try (InputStream stream = new BufferedInputStream(new FileInputStream(ENV.get("CERT_PUBLIC")))) {
                CertificateFactory factory = CertificateFactory.getInstance("X.509");
                Certificate cert = factory.generateCertificate(stream);

                PrivateKey key = RSAUtils.getPrivateKey(ENV.get("CERT_PRIVATE"));
                store.setKeyEntry("cert", key, uuid, new Certificate[]{cert});
            }

            KeyManagerFactory keyManager = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm()
            );

            keyManager.init(store, uuid);

            TrustManagerFactory trustManager = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm()
            );

            trustManager.init(store);

            SSLContext context = SSLContext.getInstance("TLSv1.2");
            context.init(keyManager.getKeyManagers(), trustManager.getTrustManagers(), new SecureRandom());

            HttpsServer server = HttpsServer.create(address, 0);
            server.setHttpsConfigurator(new HttpsConfigurator(context));

            return server;
        }

        return HttpServer.create(address, 0);
    }

}
