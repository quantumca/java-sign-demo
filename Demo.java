package io.renren.common.utils;

import okhttp3.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.management.Query;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.*;

public class Demo {

    private static OkHttpClient client = Ok3Utils.init();

    private static final String SYMBOLS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final Random RANDOM = new SecureRandom();
    static String ACCESS_KEY_ID = "";
    static String ACCESS_KEY_SECRET = "";
    static String API_PRODUCT = "https://api.orion.pki.plus/api/v1/product/list";
    static String API_CREATE = "https://api.orion.pki.plus/api/v1/certificate/create";

    public static void main(String[] args) throws Exception {
        DF.setTimeZone(new SimpleTimeZone(0, "PRC")); // 这里一定要设置GMT时区 PRC
        String nonce = CodeGenerator.getUUID();
        String timestamp = DateUtils.getDateTimeT();
        String api = API_PRODUCT;
        // System.err.println("nonce=" + nonce);
        // System.err.println("timestamp=" + timestamp);

        Map<String, String> params = new HashMap<>();
        params.put("accessKeyId", ACCESS_KEY_ID);
        params.put("nonce", nonce);
        params.put("timestamp", timestamp);

        String stringToSign = urlPathname(api) + "?" + httpBuildQuery(params);
        System.err.println("stringToSign=" + stringToSign);
        String signature = base64Encode(hmacSHA256Signature(ACCESS_KEY_SECRET, stringToSign));
        String url = api + "?" + httpBuildQuery(params) + "&sign=" + URLEncoder.encode(signature, "utf-8");
        System.out.println("url=" + url);

        requestUrl(url, "GET", null);
    }

    private static String urlPathname(String url) {
        String pathname = url.substring(url.indexOf("//") + 2);
        pathname = pathname.substring(pathname.indexOf("/"), pathname.indexOf("?"));
        return pathname;
    }

    private static String httpBuildQuery(Map<String, String> params) {
        List<String> keys = new ArrayList<>(params.keySet());
        Collections.sort(keys);
        StringBuilder queryString = new StringBuilder();
        for (String key : keys) {
            String value = params.get(key);
            if (value != null) {
                queryString.append("&").append(key).append("=").append(URLEncoder.encode(value, "utf-8"));
            } else {
                queryString.append("&").append(key).append("=").append("");
            }
        }
        return queryString.toString().substring(1);
    }

    private static void requestUrl(String url, String method, Map<String, String> params) throws Exception {
        Request request = new Request.Builder()
                .url(url)
                .build();
        Response response = client.newCall(request).execute();
        System.out.println(response.body().string());

        // TODO: 解析JSON数据
    }

    private static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] hmacSHA256Signature(String accessKeySecret, String stringToSign) {
        System.err.println("accessKeySecret=" + accessKeySecret);
        try {
            String key = accessKeySecret;
            try {
                SecretKeySpec signKey = new SecretKeySpec(key.getBytes(), "HmacSHA256");
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(signKey);
                return mac.doFinal(stringToSign.getBytes());
            } catch (Exception e) {
                throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
            }
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }
}
