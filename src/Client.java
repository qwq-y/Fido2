import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * CTAP中Token和Client都没写哈希H()（即K目前等于协同密钥），而且Client可能还没写generateK方法
 * verifyBind没有验证椭圆曲线加密（即K）
 */

public class Client {
    String clientName;
    List<Token> connectedTokens;
    List<Server> connectedServers;

    public Client(String clientName) {
        this.clientName = clientName;
        connectedTokens = new ArrayList<>();
        connectedServers = new ArrayList<>();
    }

    static String requestSetup(String pkAStr) {
        try {
            // 获取pin
            String pin = generatePin(6);
            // 返回公钥、加密（pin、对称密钥）
            return generateRst(pin, pkAStr);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static String requestBind(String pkAStr) {
        // 获取用户输入的pin
        Scanner scanner = new Scanner(System.in);
        System.out.print("Please enter your PIN: ");
        String pin = scanner.nextLine();
        scanner.close();
        // 根据pin生成pinH
        String pinH = generatePinH(pin);

        // 返回公钥、加密（pinH、对称密钥）
        String rst = generateRst(pinH, pkAStr);
        System.out.println("client return: " + rst);
        return rst;
    }

    static void verifyBind(String bindInfo) {
        try {
            String encryped = bindInfo.substring(0, 236);
            String token = bindInfo.substring(236);
            String decrypted = AESUtil.decrypt(encryped);
            String pt = decrypted.substring(0, 128);
            String kABstr = decrypted.substring(128);

            // 还没有验证椭圆曲线加密

            System.out.println("token: " + token);
            System.out.println("pt: " + pt);
            storeNamePt(token, pt);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static String authorize(String M, Token token, int type) {
        // type: 0 register, 1 authenticate
        if (type == 0) {
            System.out.println("\nAuthorize start: register!");
        } else if (type == 1) {
            System.out.println("\nAuthorize start: authenticate!");
        }

        String name = token.name;
        System.out.println("Client search pt of token: " + token);
        String pt = getPt(name);

        if (pt == null || pt.length() == 0) {
            System.err.println("Client not bind with the token yet!");
            return null;
        } else {
            String t = Utils.generateT(M, pt, "123456");    // 64 bits，这个key我目前还没了解怎么处理，所以都用的“123456”
            System.out.println("tag: " + t);
            System.out.println("message: " + M);
            return token.validate(t + M, type);
        }
    }

    private static String generatePinH(String pin) {
        String pinH = pin;
        return pinH;
    }

    private static String generateRst(String pin, String pkAStr) {
        String key = generateKey(pkAStr);
        String pkBstr = key.substring(0, 124);
        System.out.println("pkBstr: " + pkBstr);
        String kBAstr = key.substring(124);
        System.out.println("kBAstr: " + kBAstr);

        String src = pin + kBAstr;
        String encrypted = AESUtil.encrypt(src);
        System.out.println("encrypted: " + encrypted);
        String rst = pkBstr + encrypted;
        return rst;
    }

    private static String generateKey(String pkAStr) {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyGen.initialize(ecSpec);

            KeyPair keyPairB = keyGen.generateKeyPair();
            KeyAgreement kaB = KeyAgreement.getInstance("ECDH");
            kaB.init(keyPairB.getPrivate());

            // 公钥
            PublicKey publicKeyB = keyPairB.getPublic();
            String pkBstr = Base64.encodeBytes(publicKeyB.getEncoded());    // 124 bits

            // 对称密钥
            byte[] pkAbyte = Base64.decode(pkAStr);
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(pkAbyte);
            PublicKey pkA = kf.generatePublic(pkSpec);

            kaB.doPhase(pkA, true);
            byte[] kBA = kaB.generateSecret();
            String kBAstr = Base64.encodeBytes(kBA);

            return pkBstr + kBAstr;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String generatePin(int len) {
        // ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
        final String chars = "0123456789";

        SecureRandom random = new SecureRandom();
        StringBuilder sb;
        String pin;

        do {
            sb = new StringBuilder();
            for (int i = 0; i < len; i++) {
                int randomIndex = random.nextInt(chars.length());
                sb.append(chars.charAt(randomIndex));
            }
            pin = sb.toString();
        } while (isPinDuplicated(pin));

        storePin(pin);

        return pin;
    }

    private static boolean isPinDuplicated(String pin) {
        DatabaseOp dbOp = new DatabaseOp();
        dbOp.getConnection();

        String sql = "select count(*) from pin where pin = '" + pin + "'";
        String[] columbLabel = {"count"};
        String[] rst = dbOp.select(sql, columbLabel, 1);
        int cnt = Integer.parseInt(rst[0]);

        dbOp.closeConnection();

        if (cnt == 0) {
            System.out.println("New pin is not duplicated, nice");
            return false;
        } else {
            System.err.println("New pin duplicated, will auto re-generate");
            return true;
        }
    }

    private static void storePin(String pin) {
        DatabaseOp dbOp = new DatabaseOp();
        dbOp.getConnection();

        String statement = "insert into pin (pin)";
        String[] para = {pin};
        dbOp.insert(statement, para, 1);

        dbOp.closeConnection();
    }

    private static void storeNamePt(String token, String pt) {
        DatabaseOp dbOp = new DatabaseOp();
        dbOp.getConnection();

        String statement = "insert into client_lib (token, pt)";
        String[] para = {token, pt};
        dbOp.insert(statement, para, 2);

        dbOp.closeConnection();

        System.out.println("Client bound.");
    }

    private static String getPt(String token) {
        DatabaseOp dbOp = new DatabaseOp();
        dbOp.getConnection();

        String sql = "select pt from client_lib where token = '" + token + "'";
        String[] columbLabel = {"pt"};
        String[] rst = dbOp.select(sql, columbLabel, 1);
        String pt = rst[0];

        dbOp.closeConnection();
        return pt;
    }

    public void register(Token token, String intendedIds, Server server) {
        String ch = server.rChallenge();
        String[] strs = ch.split("\\.");
        String uid = strs[0];   // user id
        String r = strs[1];     // random 01
        String ids = "";        // ids from server
        try {
            ids = new String(Base64.decode(strs[2]));
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (!ids.equals(intendedIds)) {
            System.err.println("Current server is not matched with intended server, registration stopped");
        } else {
            String info = uid + "." + Utils.SHA256(r) + "." + strs[2];

            String res = Client.authorize(info, token, 0);

            if (res != null) {
                // store info
                boolean ans = server.rCheck(res);
                if (ans) {
                    System.out.println("Register successfully");
                } else {
                    System.err.println("Register failed");
                }
            } else {
                System.err.println("不是信任的客户端");
            }
        }
    }

    public void login(Token token, String intendedIds, Server server) {
        String ch = server.aChallenge();
        String[] strs = ch.split("\\.");
        String r = strs[0];
        String ids = "";
        try {
            ids = new String(Base64.decode(strs[1]));
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (!ids.equals(intendedIds)) {
            System.err.println("Current server is not matched with intended server, authentication stopped");
        } else {
            String info = Utils.SHA256(r) + "." + Base64.encodeBytes(ids.getBytes(StandardCharsets.UTF_8));

            String res = Client.authorize(info, token, 1);

            if (res != null) {
                String ans = server.aCheck(res);
                if (ans.equals("FAILED")) {
                    System.err.println("Log-in Failed");
                } else {
                    System.out.println("NOW Log-in: " + ans);
                }
            }
        }
    }
}
