package me.vitormac.mediaserver;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.cdimascio.dotenv.Dotenv;
import me.vitormac.mediacore.MediaProvider;
import me.vitormac.mediacore.data.Range;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

public class Main {

    private static final int PORT;
    private static final String ORIGIN;

    static {
        Dotenv dotenv = Dotenv.configure()
                .ignoreIfMissing().load();

        EnvUtils.check(dotenv, "PRIVATE_KEY");
        EnvUtils.check(dotenv, "PUBLIC_KEY");

        PORT = Integer.parseInt(dotenv.get("PORT", "4770"));
        ORIGIN = dotenv.get("ORIGIN", "*");
    }

    public static void main(String[] args) throws Exception {
        HttpServer server = createServer();
        server.setExecutor(Executors.newCachedThreadPool());

        server.createContext("/", (HttpExchange e) -> {
            try {
                String path = e.getRequestURI().getPath().substring(1);
                String data = RSAUtils.decrypt(path);

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

        System.out.printf("Server running at [:%d]%n", PORT);
        server.start();
    }

    private static HttpServer createServer() throws Exception {
        InetSocketAddress address = new InetSocketAddress(PORT);
        return HttpServer.create(address, 0);
    }

}
