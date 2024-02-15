import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * CTAP中Token和Client都没写哈希H()（即K目前等于协同密钥）
 */

/**
 * pkA指的是A方生成的公钥
 * kAB指的是A方生成的协同密钥
 */

public class Token {
    public String name;    // 8 bits
    private String pinH;
    private String pt;
    private int n = 8;
    private int m = 3;
    public int tokenVersion;
    List<Client> connectedClients;
    
    public Token(String name, int version) {
        this.name = name;
        tokenVersion = version;
        connectedClients = new ArrayList<>();
    }
    
    boolean setup() {
        System.out.println("\nSetup start!");
        try {
            KeyPair keyPairA = generateKeyPair();
            KeyAgreement kaA = KeyAgreement.getInstance("ECDH");
            kaA.init(keyPairA.getPrivate());
            PublicKey publicKeyA = keyPairA.getPublic();
            String pkAstr = Base64.encodeBytes(publicKeyA.getEncoded());
            System.out.println("pkAstr: " + pkAstr);
            
            // 接收client的公钥、pin、协同密钥
            // 验证ECDH，若验证通过则返回 (K + client生成的pin)，否则返回null
            String rst = Client.requestSetup(pkAstr);
            String KPin = verify(kaA, rst, 6);
            
            if (KPin != null) {
                String pin = KPin.substring(44);
                System.out.println("Token verified ECDH in setup.");
                storePin(pin);
                return true;
            } else {
                System.err.println("Risk of tampering, terminated.");
                return false;
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    
    boolean bind() {
        System.out.println("\nBind start!");
        try {
            KeyPair keyPairA = generateKeyPair();
            KeyAgreement kaA = KeyAgreement.getInstance("ECDH");
            kaA.init(keyPairA.getPrivate());
            PublicKey publicKeyA = keyPairA.getPublic();
            String pkAstr = Base64.encodeBytes(publicKeyA.getEncoded());
            
            // 接收client的公钥、pinH、协同密钥
            // 验证ECDH，若验证通过则返回(K + client计算的pinH)，否则返回null
            String rst = Client.requestBind(pkAstr);
            String KPinH = verify(kaA, rst, 6);
            
            if (KPinH != null) {
                String pinH = KPinH.substring(44);
                System.out.println("Token verified ECDH in bind.");
                if (pinH.equals(this.pinH)) {
                    System.out.println("Token bound.");
                    
                    // 把绑定信息返回给client
                    String pt = generatePt();    // 128 bits
                    String kABstr = KPinH.substring(0, 44);
                    String decrypted = AESUtil.encrypt(pt + kABstr);    // 236 bits
                    String bindInfo = decrypted + name;
                    Client.verifyBind(bindInfo);
                    
                    return true;
                } else {
                    System.err.println("Wrong PIN!");
                    System.out.println("your pinH: " + pinH + "\nthis.pinH: " + this.pinH);
                    return false;
                    
                }
            } else {
                System.err.println("Risk of tampering, terminated.");
                return false;
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
    
    String validate(String message, int type) {
        // type: 0 register, 1 authenticate
        
        String t = message.substring(0, 64);    // len取决于HMAC
        String M = message.substring(64);
        String tCal = Utils.generateT(M, pt, "123456");    // 这个key我目前还没了解怎么处理，所以都用的“123456”
        
        if (t.equals(tCal)) {
            System.out.println("Validate success!");
            if (type == 0) {
                return rResponse(M);
            } else if (type == 1) {
                return aResponse(M);
            } else {
                return null;
            }
        } else {
            System.out.println("tokenM: " + M);
            System.out.println("tM: " + t);
            System.out.println("tC: " + tCal);
            System.err.println("Validate false! Not trusted client!");
            return null;
        }
    }
    
    private String verify(KeyAgreement kaA, String rst, int len) {
        try {
            String pkBstr = rst.substring(0, 124);
            String encrypted = rst.substring(124);
            String decrypted = AESUtil.decrypt(encrypted);
            String pin = decrypted.substring(0, len);    // pin or pinH
            String kBAstr = decrypted.substring(len);
            System.out.println("kBAstr: " + kBAstr);
            
            byte[] pkBbyte = Base64.decode(pkBstr);
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(pkBbyte);
            PublicKey pkB = kf.generatePublic(pkSpec);
            
            kaA.doPhase(pkB, true);
            byte[] kAB = kaA.generateSecret();
            String kABstr = Base64.encodeBytes(kAB);    // 44 bits
            System.out.println("kABstr: " + kABstr);
            
            String K = generateK(kABstr);
            
            if (kABstr.equals(kBAstr)) {
                return K + pin;
            } else {
                return null;
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private String generatePt() {
        final String chars = "01";
        
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < 128; i++) {
            int randomIndex = random.nextInt(chars.length());
            sb.append(chars.charAt(randomIndex));
        }
        
        String pt = sb.toString();
        this.pt = pt;
        return pt;
    }
    
    private String generateK(String kABstr) {
        String K = kABstr;
        return K;
    }
    
    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
            keyGen.initialize(ecSpec);
            
            KeyPair keyPairA = keyGen.generateKeyPair();
            return keyPairA;
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private boolean storePin(String pin) {
        // 根据pin生成pinH
        String pinH = pin;
        
        
        this.pinH = pinH;
        System.out.println("Token finished setup.");
        System.out.println("PIN: " + pin);
        return true;
    }
    
    public String rResponse(String info) {
        System.out.println("\nrResponse start!");
        String[] strs = info.split("\\.");
        String uid = strs[0];
        String hr = strs[1];
        String ids = "";
        
        try {
            ids = new String(Base64.decode(strs[2]));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String[] kg = keyGen();
        String pk = kg[0];
        String sk = kg[1];
        int n = 0;
        String cid = Utils.getRandom01(128);
        String ad = Utils.SHA256(ids) + "." + n + "." + cid + "." + pk;
        
        //sign
        byte[] signData = (ad + hr).getBytes(StandardCharsets.UTF_8);
        byte[] signature = Utils.sign(signData, PKI.getPrivateKey(tokenVersion));
        String sigma = Base64.encodeBytes(signature);
        
        // store the information into database
        DatabaseOp db = new DatabaseOp();
        db.getConnection();
        String statement = "insert into token_credential_info(token,ids,cid,n,sk,uid) ";
        String[] para = {name, ids, cid, String.valueOf(n), sk, uid};
        db.insert(statement, para, 6);
        db.closeConnection();
        
        System.out.println("uid: " + uid);
        System.out.println("hr: " + hr);
        System.out.println("ids: " + ids);
        System.out.println("sigma: " + sigma);
        
        return ad + "." + sigma;
    }
    
    public String aResponse(String info) {
        System.out.println("\naResponse start!");
        String[] strs = info.split("\\.");
        String hr = strs[0];
        String ids = strs[1];
        try {
            ids = new String(Base64.decode(ids));
        } catch (Exception e) {
            e.printStackTrace();
        }
        // select from database according to ids
        DatabaseOp db = new DatabaseOp();
        db.getConnection();
        String sql = "select * from token_credential_info where token = '" + name + "' and ids = '" + ids + "'";
        String[] columbLabel = {"uid", "cid", "sk", "n"};
        String[] rst = db.select(sql, columbLabel, 4);
        if (rst[0] == null) {
            System.err.println("No token_credential_info found!");
            return null;
        }
        
        String uid = rst[0];
        String cid = rst[1];
        String skstr = rst[2];
        String nStr = rst[3];
//        System.err.println(sql);
        int n = Integer.parseInt(nStr);
        n++;
        //ad
        StringBuilder ad = new StringBuilder();
        ad.append(Utils.SHA256(ids));
        ad.append(".");
        ad.append(n);
        String adstr = ad.toString();
        //sign
        String signDataStr = adstr + hr;
        byte[] signData = signDataStr.getBytes(StandardCharsets.UTF_8);
        PrivateKey sk = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decode(skstr));
            sk = keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] signature = Utils.sign(signData, sk);
        String sigma = Base64.encodeBytes(signature);
        // update credential info
        String sql2 = "update token_credential_info set n = '" + n + "' where token = '" + name + "' and ids = '" + ids + "'";
        db.updateOrDelete(sql2);
        db.closeConnection();
        return cid + "." + ad + "." + sigma + "." + uid;
    }
    
    public static String[] keyGen() {
        String[] ans = new String[2];
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair;
            PublicKey publicKey;
            PrivateKey privateKey;
            for (int i = 0; i < 100; i++) {
                pair = generator.generateKeyPair();
                // 提取公私钥，转化成String
                publicKey = pair.getPublic();
                privateKey = pair.getPrivate();
                ans[0] = Base64.encodeBytes(publicKey.getEncoded());    // public key str
                ans[1] = Base64.encodeBytes(privateKey.getEncoded());   // private key str
                if (ans[1].length() == 1624) {
                    break;
                }
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return ans;
    }
}
