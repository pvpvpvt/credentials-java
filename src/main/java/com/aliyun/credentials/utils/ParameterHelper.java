package com.aliyun.credentials.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.SimpleTimeZone;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.aliyun.credentials.configure.Config;
import com.aliyun.credentials.exception.CredentialException;

public class ParameterHelper {
    private final static String TIME_ZONE = "UTC";
    private final static String FORMAT_ISO8601 = "yyyy-MM-dd'T'HH:mm:ss'Z'";
    private final static String SEPARATOR = "&";
    public static final String ENCODING = "UTF-8";
    private static final String ALGORITHM_NAME = "HmacSHA1";
    private static AtomicLong seqId = new AtomicLong(0);
    private static final long processStartTime = System.currentTimeMillis();

    public static String getUniqueNonce() {
        // thread id
        long threadId = Thread.currentThread().getId();
        // timestamp: ms
        long currentTime = System.currentTimeMillis();
        // sequence number
        ThreadLocalRandom random = ThreadLocalRandom.current();
        long seq = seqId.getAndIncrement();
        long rand = random.nextLong();

        StringBuffer sb = new StringBuffer();
        sb.append(processStartTime).append('-')
                .append(threadId).append('-')
                .append(currentTime).append('-')
                .append(seq).append('-')
                .append(rand);
        try {
            // hash
            MessageDigest digest = MessageDigest.getInstance("MD5");
            // hex
            byte[] msg = sb.toString().getBytes();
            sb.setLength(0);
            for (byte b : digest.digest(msg)) {
                String hex = Integer.toHexString(b & 0xFF);
                if (hex.length() < 2) {
                    sb.append(0);
                }
                sb.append(hex);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new CredentialException(e.getMessage(), e);
        }
        return sb.toString();
    }


    public static String getISO8601Time(Date date) {
        SimpleDateFormat df = new SimpleDateFormat(FORMAT_ISO8601);
        df.setTimeZone(new SimpleTimeZone(0, TIME_ZONE));
        return df.format(date);
    }

    public static Date getUTCDate(String date) {
        SimpleDateFormat df = new SimpleDateFormat(FORMAT_ISO8601);
        df.setTimeZone(new SimpleTimeZone(0, TIME_ZONE));
        try {
            return df.parse(date);
        } catch (ParseException e) {
            throw new CredentialException(e.getMessage(), e);
        }
    }

    public static String getTimeString(long milliseconds) {
        Date date = new Date(milliseconds);
        SimpleDateFormat df = new SimpleDateFormat(FORMAT_ISO8601);
        return df.format(date);
    }

    public String signString(String stringToSign, String accessKeySecret) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM_NAME);
            mac.init(new SecretKeySpec(accessKeySecret.getBytes(ENCODING), ALGORITHM_NAME));
            byte[] signData = mac.doFinal(stringToSign.getBytes(ENCODING));
            return Base64.encodeBase64String(signData);
        } catch (Exception e) {
            throw new CredentialException(e.getMessage(), e);
        }

    }

    public static String composeUrl(String endpoint, Map<String, String> queries, String protocol) {
        Map<String, String> mapQueries = queries;
        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append(protocol);
        urlBuilder.append("://").append(endpoint);
        urlBuilder.append("/?");
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : mapQueries.entrySet()) {
            String key = entry.getKey();
            String val = entry.getValue();
            if (val == null) {
                continue;
            }
            builder.append(AcsURLEncoder.encode(key));
            builder.append("=").append(AcsURLEncoder.encode(val));
            builder.append("&");
        }

        int strIndex = builder.length();
        builder.deleteCharAt(strIndex - 1);
        String query = builder.toString();
        return urlBuilder.append(query).toString();
    }

    /**
     * Hex encode for byte array.
     *
     * @param raw byte array
     * @return encoded string
     */
    public static String hexEncode(byte[] raw) {
        if (raw == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : raw) {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() < 2) {
                sb.append(0);
            }
            sb.append(hex);
        }
        return sb.toString();
    }

    /**
     * Hash the raw data with HMAC-SHA256.
     *
     * @param raw hashing data
     * @return hashed bytes
     */
    public static byte[] hashSHA256(byte[] raw) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(raw);
    }

    /**
     * HmacSHA256 Signature
     *
     * @param stringToSign string
     * @param secret       bytes
     * @return signed bytes
     */
    private static byte[] HmacSHA256Sign(String stringToSign, byte[] secret) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(secret, "HmacSHA256");
        sha256_HMAC.init(secret_key);
        return sha256_HMAC.doFinal(stringToSign.getBytes());
    }

    private static byte[] getSigningkey(String secret, String product, String region, String date) throws Exception {
        byte[] sc1 = (Config.SIGN_PREFIX + secret).getBytes(StandardCharsets.UTF_8);
        byte[] sc2 = HmacSHA256Sign(date, sc1);
        byte[] sc3 = HmacSHA256Sign(region, sc2);
        byte[] sc4 = HmacSHA256Sign(product, sc3);
        return HmacSHA256Sign(Config.SIGN_PREFIX + "_request", sc4);
    }

    public static String getAuthorization(String pathname, String method, java.util.Map<String, String> query, java.util.Map<String, String> headers, String payload, String ak, String secret, String product, String region, String date) throws Exception {
        byte[] signingkey = getSigningkey(secret, product, region, date);
        String signature = getSignature(pathname, method, query, headers, payload, signingkey);
        java.util.List<String> signedHeaders = getSignedHeaders(headers);
        return Config.SIGNATURE_TYPE_PREFIX + "HMAC-SHA256 Credential=" + ak + "/" + date + "/" + region + "/" + product
                + "/" + Config.SIGN_PREFIX + "_request,SignedHeaders="
                + StringUtils.join(signedHeaders, ";") + ",Signature=" + signature;
    }

    private static String getSignature(String pathname, String method, java.util.Map<String, String> query, java.util.Map<String, String> headers, String hashedRequestPayload, byte[] signingkey) throws Exception {
        String canonicalURI = "/";
        if (!StringUtils.isEmpty(pathname)) {
            canonicalURI = pathname;
        }
        String canonicalizedResource = buildCanonicalizedResource(query);
        String canonicalizedHeaders = buildCanonicalizedHeaders(headers);
        java.util.List<String> signedHeaders = getSignedHeaders(headers);
        String stringToSign = method + "\n" + canonicalURI + "\n" + canonicalizedResource + "\n" + canonicalizedHeaders + "\n" + StringUtils.join(signedHeaders, ";") + "\n" + hashedRequestPayload;
        stringToSign = Config.SIGNATURE_TYPE_PREFIX + "HMAC-SHA256\n" + hexEncode(hashSHA256(stringToSign.getBytes()));
        byte[] signature = HmacSHA256Sign(stringToSign, signingkey);
        return hexEncode(signature);
    }

    private static String buildCanonicalizedResource(java.util.Map<String, String> query) {
        StringBuilder canonicalizedResource = new StringBuilder();
        if (query != null) {
            List<String> queryArray = new ArrayList<>(query.keySet());
            String[] sorted = queryArray.toArray(new String[0]);
            Arrays.sort(sorted);
            String separator = "";
            for (String key : sorted) {
                canonicalizedResource.append(separator).append(AcsURLEncoder.percentEncode(key)).append("=");
                if (!StringUtils.isEmpty(query.get(key))) {
                    canonicalizedResource.append(AcsURLEncoder.percentEncode(query.get(key)));
                }
                separator = "&";
            }
        }

        return canonicalizedResource.toString();
    }

    private static String buildCanonicalizedHeaders(java.util.Map<String, String> headers) throws Exception {
        StringBuilder canonicalizedHeaders = new StringBuilder();
        java.util.List<String> sortedHeaders = getSignedHeaders(headers);
        for (String header : sortedHeaders) {
            canonicalizedHeaders.append(header).append(":").append(headers.get(header).trim()).append("\n");
        }
        return canonicalizedHeaders.toString();
    }

    private static java.util.List<String> getSignedHeaders(java.util.Map<String, String> headers) throws Exception {
        List<String> headersArray = new ArrayList<>(headers.keySet());
        String[] sorted = headersArray.toArray(new String[0]);
        Arrays.sort(sorted);
        List<String> signedHeaders = new ArrayList<>();
        for (String key : sorted) {
            String lowerKey = key.toLowerCase();
            if (lowerKey.startsWith("x-acs-")) {
                signedHeaders.add(lowerKey);
            }

        }
        return signedHeaders;
    }

    public static String getRegion(String endpoint) {
        String region = "center";
        if (!StringUtils.isEmpty(endpoint)) {
            String preRegion = endpoint.replace("." + Config.ENDPOINT_SUFFIX, "");
            List<String> nodes = Arrays.asList(preRegion.split("\\."));
            if (nodes.size() == 2) {
                region = nodes.get(1);
            }
        }
        return region;
    }
}
