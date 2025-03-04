package com.aliyun.credentials.http;


import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class HttpRequest extends HttpMessage {
    private Map<String, String> immutableMap = new HashMap<String, String>();

    public HttpRequest() {
    }

    public HttpRequest(String url) {
        super(url);
    }

    public void setUrlParameter(String key, String value) {
        this.immutableMap.put(key, value);
    }

    public String getUrlParameter(String key) {
        return this.immutableMap.get(key);
    }

    public Map<String, String> getUrlParameters() {
        return Collections.unmodifiableMap(immutableMap);
    }

}
