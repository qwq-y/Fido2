import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class Server {
    String ids;
    String curUid;
    String curRs;
    List<Client> connectedClients;
    
    public Server(String ids) {
        this.ids = ids;
        connectedClients = new ArrayList<>();
    }
    
    public String rChallenge() {
        StringBuilder sb = new StringBuilder();
        curUid = Utils.getRandom01(128);
        sb.append(curUid);
        sb.append('.');
        curRs = Utils.getRandom01(128);
        sb.append(curRs);
        sb.append('.');
        sb.append(Base64.encodeBytes(ids.getBytes(StandardCharsets.UTF_8)));
        // send to client??
        // hostname 不定长 已使用b64编码 + '.'分隔处理
        return sb.toString();
    }
    
    public String aChallenge() {
        StringBuilder sb = new StringBuilder();
        String rs = Utils.getRandom01(128);
        curRs = rs;
        sb.append(rs);
        sb.append(".");
        sb.append(Base64.encodeBytes(ids.getBytes(StandardCharsets.UTF_8)));
        // send to client
        return sb.toString();
    }
    
    boolean rCheck(String res) {
        String[] response = res.split("\\.");
        String idsSHA = response[0];
        int n = Integer.parseInt(response[1]);
        String cid = response[2];
        String pk = response[3];
        byte[] sigma = null;
        try {
            sigma = Base64.decode(response[4]);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // verify signature
        String signstr = idsSHA + "." + n + "." + cid + "." + pk + Utils.SHA256(curRs);
        byte[] signData = signstr.getBytes(StandardCharsets.UTF_8);
        boolean sigIsRight = Utils.verify(signData, PKI.getPublicKey(0), sigma);
        if (!sigIsRight) {
            System.err.println("签名验证失败");
            return false;
        }
        if (n != 0 || !idsSHA.equals(Utils.SHA256(ids))) {
            System.err.println("其他错误");
            return false;
        }
        //store info
        DatabaseOp db = new DatabaseOp();
        db.getConnection();
        String statemet = "insert into server_credential_info(ids,cid,uid,n,pk) ";
        String[] para = {ids, cid, curUid, String.valueOf(n), pk};
        db.insert(statemet, para, 5);
        db.closeConnection();
        return true;
    }
    
    String aCheck(String res) {
        String ans = "??";
        String[] response = res.split("\\.");
        String cid = response[0];
        String idsSHA = response[1];
        int nt = Integer.parseInt(response[2]);
        String sigma = response[3];
        String uid = response[4];
        //check... select and compare
        if (!idsSHA.equals(Utils.SHA256(ids))) {
            System.err.println("Wrong ids");
            return "FAILED";
        }

        DatabaseOp db = new DatabaseOp();
        db.getConnection();
        String sql = "select * from server_credential_info where cid = '" + cid + "' and ids = '" + ids + "'";
        String[] columbLabel = {"n", "pk", "uid"};
        String[] rst = db.select(sql, columbLabel, 3);
        int n = Integer.parseInt(rst[0]);
        String pkstr = rst[1];
        ans = rst[2];

        if (nt <= n) {
            System.out.printf("nt = %d n = %d", nt, n);
            return "FAILED";
        }

        String signDataStr = idsSHA + "." + nt + Utils.SHA256(curRs);
        byte[] signData = signDataStr.getBytes(StandardCharsets.UTF_8);
        byte[] sigmaData = null;
        PublicKey pk = null;
        try {
            sigmaData = Base64.decode(sigma);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(pkstr));
            pk = keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        boolean sigmaOK = Utils.verify(signData,pk,sigmaData);
        if(!sigmaOK){
            System.err.println("签名验证失败");
            return "FAILED";
        }

        //update credential info
        String sql2 = "update server_credential_info set n = '" + nt + "' where cid = '" + cid + "' and ids = '" + ids+"'";
        db.updateOrDelete(sql2);
        db.closeConnection();
        return ans;
    }
    
//    private Object[] adDecoder(String ad, boolean r) {
//        Object[] ans;
//        if (r) {
//            ans = new Object[4];
//            String h = ad.substring(0, 64);
//            ans[0] = h;
//            int n = Utils.binToInt(ad.substring(64, 96));
//            ans[1] = n;
//            String cid = ad.substring(96, 224);
//            ans[2] = cid;
//            String pk = ad.substring(224);
//            ans[3] = pk;
//        } else {
//            ans = new Object[3];
//            String h = ad.substring(0, 64);
//            ans[0] = h;
//            int nt = Utils.binToInt(ad.substring(64, 96));
//            ans[1] = nt;
//            String cid = ad.substring(96);
//            ans[2] = cid;
//        }
//        return ans;
//    }
}
