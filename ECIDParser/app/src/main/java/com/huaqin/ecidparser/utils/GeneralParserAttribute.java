package com.huaqin.ecidparser.utils;
import android.os.SystemProperties;
/**
 * Created by shiguibiao on 16-8-3.
 */

public interface GeneralParserAttribute {

    //<2015/11/24-junam.hwang, [D5][PORTING][COMMON][FLEX2][][] change flex path with property
    public static final String Flex_Path = SystemProperties.get("ro.lge.flex.rootdir", "system/etc/");

    public static final String FILE_PATH_TELEPHONY_PROFILE = Flex_Path + "telephony.xml";
    public static final String FILE_PATH_TELEPHONY_CONFIG = Flex_Path + "telephony_config.xml";
    public static final String FILE_PATH_FEATURE_OPEN = Flex_Path + "featureset.xml";
    public static final String FILE_PATH_CONTACT_SETTINGS = Flex_Path + "contacts_setting.xml";
    public static final String FILE_PATH_BROWSER_CONFIG = Flex_Path + "browser_config.xml";
    public static final String FILE_PATH_MMS_CONFIG = Flex_Path + "mms_config.xml";
    public static final String FILE_PATH_CB_CONFIG = Flex_Path + "cb_config.xml";
    public static final String FILE_PATH_EMAIL_CONFIG = Flex_Path + "email_config.xml";
    public static final String FILE_PATH_SETTINGS_PROVIDER_CONFIG = Flex_Path + "settings_provider_config.xml";
    public static final String FILE_PATH_LTE_READY_CONFIG = Flex_Path + "lteready.xml";

    public static final String OPERATOR = "ro.product.carrier"; //"ro.build.target_operator"
    public static final String COUNTRY = "ro.product.country"; //"ro.build.target_country"

    public static final String SYSTEM_PROP_CUPSS_ROOTDIR = "ro.lge.flex.rootdir"; // Flex Root Directory
    public static final String SYSTEM_PROP_CUPSS_SUBCA = "persist.sys.cupss.subca-prop";  // OPEN_COM Sub CA Prop
    //>2015/11/24-junam.hwang


    // [Profile names]
    public static final String ATTR_NAME = "name";
    public static final String ATTR_VALUE = "value";
    public static final String ATTR_URL = "url";


    public static final String ELEMENT_NAME_PROFILES = "profiles";
    public static final String ELEMENT_NAME_PROFILE = "profile";
    public static final String ELEMENT_NAME_SIMINFO = "siminfo";
    public static final String ELEMENT_NAME_COMMONPROFILE = "CommonProfile";
    public static final String ELEMENT_NAME_FEATURESET = "FeatureSet";
    public static final String ELEMENT_NAME_ITEM = "item";
    public static final String ELEMENT_NAME_HOMEPAGE = "homepage";
    public static final String ELEMENT_NAME_BOOKMARK = "bookmark";

    //Setting provider
    public static final String ELEMENT_NAME_SYSTEMPROPERTY = "SystemProperty";
    public static final String ELEMENT_NAME_SETTINGSSYSTEM = "Settings.System";
    public static final String ELEMENT_NAME_SETTINGSSECURE = "Settings.Secure";


    // [START] Only browser feature
    public static final String ELEMENT_NAME_SINGLEBINARY = "singlebinary";
    public static final String ELEMENT_NAME_READONLY = "bookmark_read_only";

    public final static int MATCHCNT = 5;
    // LGE_WEB [[ alice.ohe 20140410 Auto profile parser bug fix
    public final static int CANDIDATECNT = 1;
    public final static int NO_MATCH = -1;
    public final static int FIND_DEFAULT = 0;
    public final static int FIND_BESTMATCH = 15;
    public static final String LOG_TAG = "AUTOPROP";
    // LGE_WEB ]] alice.ohe 20140410 Auto profile parser bug fix
    // [END] Only browser feature


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




    /*<item name="VMS">       	==>*/
    public static final String ID_VOICE_MAIL_IN_HOME_NUMBER ="Message@Voice_Mail_In_Home_Number";
    /*<item name="RVMS">*/
    public static final String ID_VOICE_MAIL_IN_ROAMING_NUMBER="Message@Voice_Mail_In_Roaming_Number";
    /*<item name="ECC_list">*/
    public static final String ID_ONESW_EM_NUMBER_WITH_SIM ="Network@Emergency_Numbers_Additional_numbers_With_SIM_Card";
    /*	<item name="ShortCodeCall">*/
    public static final String ID_ONESW_SHORT_CALL_SHORT_NUMBER = "Network@Short_Call_Code_Short_Number";
}
