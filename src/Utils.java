import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Random;

public class Utils {

    public static String getRandom01(int length) {
        SecureRandom r = new SecureRandom();
        int bound = 1 << 8;
        byte[] bytes = new byte[length / 8];
        r.nextBytes(bytes);
        return byteToHex(bytes);
    }

    public static String SHA256(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        byte[] ans = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(bytes);
            ans = md.digest();
        } catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        }
        return byteToHex(ans);
    }

    private static String byteToHex(byte[] a) {
        StringBuilder sb = new StringBuilder();
        for (byte b : a) {
            String tmp = Integer.toHexString(b & 0xff);
            // & 0xff becauese (int)byte would do sign-extension
            if (tmp.length() == 1) {
                sb.append("0");
                // 1 byte = 8 bit , so tmp shall be of length 2, if it's 1, 0 shall be located before
            }
            sb.append(tmp);
        }
        return sb.toString();
    }

    public static String intToBinStr(int n) {
        StringBuilder sb = new StringBuilder();
        byte[] bits = new byte[32];
        for (int i = 31; i >= 0; i--) {
            bits[i] = (byte) (n & 1);
            n = n >> 1;
        }
        for (int i = 0; i < 32; i++) {
            sb.append(bits[i]);
        }
        return sb.toString();
    }

    public static int binToInt(String s) {
        int ans = 0;
        int bi = 1;
        for (int i = 31; i >= 0; i--) {
            char c = s.charAt(i);
            ans += s.charAt(i) == '1' ? bi : 0;
            bi = bi << 1;
        }
        return ans;
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static boolean verify(byte[] data, PublicKey publicKey, byte[] sign) {
        if (sign == null) {
            System.out.println("Null public key!");
            return false;
        }
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sign);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    public static String generateT(String M, String pt, String key) {
        String msg = pt + M;
        String t = Utils.SHA256(msg);

//        try {
//            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
//            Mac mac = Mac.getInstance("HmacSHA256");
//            mac.init(secretKeySpec);
//            t = Base64.encodeBytes(mac.doFinal(Base64.decode(msg)));
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

        return t;
    }

}
