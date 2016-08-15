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

    public static final String ELEMENT_NAME_NOTIFICATION = "notification";
    public static final String ELEMENT_NAME_SIGNATURE = "signature";
    public static final String ELEMENT_NAME_ESP = "esp";
    public static final String ELEMENT_NAME_CONTACT = "contact";
    public static final String ELEMENT_NAME_CALENDAR = "calendar";
    public static final String ELEMENT_NAME_TASKS = "tasks";
    public static final String ELEMENT_NAME_SMS = "sms";
    public static final String ELEMENT_NAME_PROTOCOL = "protocol";
    public static final String ELEMENT_NAME_INCOMING = "incoming";
    public static final String ELEMENT_NAME_OUTGOING = "outgoing";

    public static final String ATTR_NAME_ENABLE = "enabled";
    public static final String ATTR_NAME_SYNC= "sync";
    public static final String ATTR_NAME_MODE= "mode";

    public static final String ATTR_NAME_SYNC_ROAMING= "syncRoaming";
    public static final String ATTR_NAME_SYNC_INTERVAL= "syncInterval";
    public static final String ATTR_NAME_POP_POLICY= "popDeletePolicy";
    public static final String ATTR_NAME_EASPROXY =  "easProxy";
    public static final String ATTR_NAME_IN_PEAK =  "updateScheduleInPeak";
    public static final String ATTR_NAME_OFF_PEAK =  "updateScheduleOffPeak";

    public static final String ATTR_NAME_DOMAIN= "domain";
    public static final String ATTR_NAME_EMAIL= "email";

    public static final String ATTR_NAME_ADDRESS= "address";
    public static final String ATTR_NAME_PROTOCOL =  "protocol";
    public static final String ATTR_NAME_PORT =  "port";
    public static final String ATTR_NAME_SECURITY =  "security";
    public static final String ATTR_NAME_USERNAME =  "username";
    public static final String ATTR_NAME_PASSWORD =  "password";
    public static final String ATTR_NAME_AUTH =  "auth";



}
