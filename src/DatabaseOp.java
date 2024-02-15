import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.sql.*;

public class DatabaseOp {
    public Connection con = null;
    private String host, dbname, user, password, port;

    public DatabaseOp(String host, String dbname, String user, String password, String port) {
        this.host = host;
        this.dbname = dbname;
        this.user = user;
        this.password = password;
        this.port = port;
    }

    public DatabaseOp() {
        host = "localhost";
//        dbname = "fido2";
        user = "postgres";
//        password = "hhxx123.";
        port = "5432";

        try {
            BufferedReader in = new BufferedReader(new FileReader("src/DatabaseLogInfo.log"));
            dbname = in.readLine();
            password = in.readLine();
//            System.out.println("dbname: " + dbname + "\tpassword: " + password);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void getConnection() {
        try {
            Class.forName("org.postgresql.Driver");
        } catch (Exception e) {
            System.err.println("Cannot find the PostgreSQL driver. Check CLASSPATH.");
            System.exit(1);
        }

        try {
            String url = "jdbc:postgresql://" + host + ":" + port + "/" + dbname;
            con = DriverManager.getConnection(url, user, password);

        } catch (SQLException e) {
            System.err.println("Database connection failed");
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    public void closeConnection() {
        if (con != null) {
            try {
                con.close();
                con = null;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public void insert(String statement, String[] para, int paraNum) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < paraNum; i++) {
            sb.append("?,");
        }
        sb.deleteCharAt(sb.length()-1);
        String sql = statement + "values (" + sb.toString() + ")";
        try {
            PreparedStatement ps = con.prepareStatement(sql);
            for (int i = 0; i < paraNum; i++) {
                ps.setString(i + 1, para[i]);
            }
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void updateOrDelete(String sql) {
        try {
            PreparedStatement ps = con.prepareStatement(sql);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public String[] select(String sql, String[] columbLabel, int cnt) {
        try {
            Statement stmt = con.createStatement();
            ResultSet rs = stmt.executeQuery(sql);
            String[] rst = new String[cnt];
            while (rs.next()) {
                for (int p = 0; p < cnt; p++) {
                    rst[p] = rs.getString(columbLabel[p]);
//                    System.err.println("SELECT " + p + " " + rst[p]);
                }
            }

            rs.close();
            stmt.close();
            return rst;

        } catch (Exception e) {
            e.printStackTrace();
            System.err.println(e.getClass().getName() + ": " + e.getMessage());
            System.exit(0);
        }
        return null;
    }
}
