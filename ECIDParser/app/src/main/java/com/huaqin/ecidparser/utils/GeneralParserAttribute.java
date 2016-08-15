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



    public static final String ELEMENT_NAME_PROFILES = "profiles";
    public static final String ELEMENT_NAME_PROFILE = "profile";
    public static final String ELEMENT_NAME_SIMINFO = "siminfo";
    public static final String ELEMENT_NAME_COMMONPROFILE = "CommonProfile";
    public static final String ELEMENT_NAME_FEATURESET = "FeatureSet";
    public static final String ELEMENT_NAME_ITEM = "item";

    public static final String ATTR_NAME = "name";
    public static final String ATTR_VALUE = "value";


    public final static int FIND_CANDIDATE_MATCH = 1;
    public final static int NO_MATCH = -1;
    public final static int FIND_DEFAULT_MATCH = 0;
    public final static int FIND_BEST_MATCH = 2;



}
