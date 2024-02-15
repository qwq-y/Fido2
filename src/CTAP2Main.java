import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class CTAP2Main {
    public static void main(String[] args) throws IOException {
        Token token = new Token("test1633", 0);
        token.setup();
        token.bind();
        Client client = new Client("123");
        Server server = new Server("example.com");
        client.register(token,"example.com",server);
        client.login(token,"example.com",server);
        client.login(token,"example.com",server);
        client.login(token,"example.com",server);
        client.login(token,"example.com",server);
    }
}
