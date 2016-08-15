package com.huaqin.ecidparser.email;

/**
 * Created by shiguibiao on 16-8-10.
 */

public interface EmailParserAttribute {
    //Emailconfig flag start
    public static final int FLAG_NONE         = 0x00;    // No flags
    public static final int FLAG_SSL          = 0x01;    // Use SSL
    public static final int FLAG_TLS          = 0x02;    // Use TLS
    public static final int FLAG_AUTHENTICATE = 0x04;    // Use name/password for authentication
    public static final int FLAG_TRUST_ALL    = 0x08;    // Trust all certificates
    // Mask of settings directly configurable by the user
    public static final int USER_CONFIG_MASK  = 0x0b;
    public static final int FLAG_TLS_IF_AVAILABLE = 0x10;
    public static final String EAS_PORT_NUMBER_SECURE_OFF = "80";
    public static final String POP_PORT_NUMBER_SECURE_OFF = "110";
    public static final String SMTP_PORT_NUMBER_SECURE_OFF = "25";
    public static final String IMAP_PORT_NUMBER_SECURE_OFF = "143";
    //Email flag end

    public static final String ELEMENT_NAME_SETTINGS = "settings";
    public static final String ELEMENT_NAME_PROVIDERS = "providers";
    public static final String ELEMENT_NAME_PROVIDER_ITEM = "provider";

    public static final String ATTR_NOTIFICATION = "name";
    public static final String ATTR_SIGNATURE = "value";
    public static final String ATTR_ESP = "value";
}
