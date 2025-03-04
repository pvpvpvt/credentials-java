package com.aliyun.credentials.utils;

import java.util.List;

public class StringUtils {

    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.length() == 0;
    }

    public static String join(List<String> raw, String sep) {
        if (null == raw || sep == null) {
            throw new IllegalArgumentException("not a valid value for parameter");
        }
        if (raw.size() > 0) {
            String result = raw.get(0);
            for (int i = 1; i < raw.size(); i++) {
                result = result + sep + raw.get(i);
            }
            return result;
        }
        return raw.toString();
    }
}
