import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PKI {
    private static final String[] publicKeys = {
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgFJ9AUo+SDu/Mf0p4w92tyI/xUkZdjAymhQXOVZkILiA1a2L3i5y19NfF0xlWvnYEW4Zs9ZHudFmTcpGLMvHvdwFjGF8S9i7UgVBwQ8mh7iBsXtxBwIxZqBLOUm/FkF1m60E9uWXj4eihkufwh04xeVjQ9rDHgnEaaGAOOUVygot8H8Tm0BKgpT5qV8p/98+tPqRk+tF+mGWP+G3K4s1BiuDnYOyTq2HSoRoHGe06gfsGjeAvwxKpA/zhC7s4luR5q9WGWdA4fv/FIN9eJd4zJyWtOH7duhfNIQzrEuf2seCOPC9gnerhcBoRNBKJEQzS1Vv5Wu0p34bkpppqRRJ8wIDAQAB"
    };
    private static final String[] privateKeys = {
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCAUn0BSj5IO78x/SnjD3a3Ij/FSRl2MDKaFBc5VmQguIDVrYveLnLX018XTGVa+dgRbhmz1ke50WZNykYsy8e93AWMYXxL2LtSBUHBDyaHuIGxe3EHAjFmoEs5Sb8WQXWbrQT25ZePh6KGS5/CHTjF5WND2sMeCcRpoYA45RXKCi3wfxObQEqClPmpXyn/3z60+pGT60X6YZY/4bcrizUGK4Odg7JOrYdKhGgcZ7TqB+waN4C/DEqkD/OELuziW5Hmr1YZZ0Dh+/8Ug314l3jMnJa04ft26F80hDOsS5/ax4I48L2Cd6uFwGhE0EokRDNLVW/la7SnfhuSmmmpFEnzAgMBAAECggEALok7qjcZhSqduOw9v4mBHQL/q3VKFZF/GF+G2JVa9H7UwikQ2z9vCJQwHQvoieinkhKioZRpKJsnBbkAYAh65IChRnqoD/2GWUVsxi3PZFLmPc4tfEQwVC53eUwkT1bn5tAFR+CVaUjgCOHuCwB78VCyAg6YyhDyuPgHvxpdH4qz+Soo0fqh+2PlT6fb/SRjU5pJ1g6ZpqQ3BRXWDczOiPDZVFp9eArLfSpeBH5NpDBjlmjSd4PU3feUbJlA6Lqvv9H58BW4+mMt/QPEgaRSDeV8UJ5uYHNXs0dvi9LLrYk8SkQ0vu8pvSicYj+LjniTO1Q/WIXbwKx8V3zVxjsmQQKBgQC7zaeJT6L1X59ACKdwyBShX7p85H/7o6F2xZFL1y0ClzrVxXqJWNV6mPLkNJ1F0eFKg1hzWEa1J3Bdg6SwmskTcAS3ySV19wC0BKoHFMBU093/mINHGpimMhfjLNXJjlqxQvDgKGd+Ao0IFo7twTbm89yifFDo2Xnmz53kttsnUwKBgQCu62wpcx5clEkN+3EktwGpTMnMD9PnXsFEszAVHtjgtvaZsFA7BJkCtYimB7wbVPcJF6MUVaGt5YfJvsY3C4FiVZoLSROEy8POeArSSSlyYkk5fzLjHquvlrWSTq84ihdhc6E9PGDu6tk5slJ9P/Jy3xZeF6D7MUVULoDECFke4QKBgDIelkGM4T5+wG9EX/s3SlouxAQkrwsnBiY+X6JP0JFKbscyJpuU+5P2UYwZhodllaxfFTHjMyuRVOmAAmmnRVZMpNWvdrHes29Xd1DgdtuslyhpOU+2h1qDL+DOzFc4CHgaF1KbNdNpNt4btxU4ZUCJgC5U4vrhXyj763VoX2BFAoGAMByc8YGydjBrL6dbZYfYsyJl1vT7igYsDqNitEx5xsVMatVuG+2V0ILyBQjXmoTyNdQEjRFImTYq9Ti9+GH3wn5dEoGVFs+dGes2vsRU3BtgnKn56zKCcpd3dbiixWBmMe3GCbvTxaNfAFmmCsFOBH6L/nFtW+ofcZog3MqXCMECgYEAs1TgFWyMrzNCkluEAGN6wYnBeMikrh9hWgQs3TWigT0f4oJKzMFU+QQVyX4HzlNzTLeOdZcth3xhceEH3bwyKP+ShPsjXqJfbfo8E5jF1wbTgkRS4DTD9ZGf7GdUDxiyFKa3UCPMNujfb2RIg8qqBXyDNOMqtjYmfr1i4QcYYtw="
    };
    
    public static PublicKey getPublicKey(int version) {
        String pkstr = publicKeys[version % publicKeys.length];
        PublicKey pk = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.decode(pkstr));
            pk = keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pk;
    }
    
    public static PrivateKey getPrivateKey(int version) {
        String skstr = privateKeys[version % privateKeys.length];
        PrivateKey sk = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.decode(skstr));
            sk = keyFactory.generatePrivate(privateKeySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sk;
    }
}
