package com.aliyun.credentials.configure;

public class Config {
    public final static String STS_DEFAULT_ENDPOINT = "{{sts_default_endpoint}}";
    public final static String ENDPOINT_SUFFIX = "{{endpoint_suffix}}";
    public final static String CONFIG_PATH = "{{config_path}}";
    public final static String ENV_PREFIX = "{{env_prefix}}";
    public final static String USER_AGENT_PREFIX = "{{user_agent_prefix}}";
    public final static String PROPERTIES_PREFIX = "{{properties_prefix}}";

    public final static String METADATA_HOST = "{{metadata_host}}";
    public final static String IMDS_HEADER_PREFIX = "{{imds_header_prefix}}";
    public final static String CREDENTIAL_FILE_PATH = "{{credential_file_path}}";
    public final static String SIGN_PREFIX = "{{sign_prefix}}";
    public final static String SIGNATURE_TYPE_PREFIX = "{{signature_type_prefix}}";
}
