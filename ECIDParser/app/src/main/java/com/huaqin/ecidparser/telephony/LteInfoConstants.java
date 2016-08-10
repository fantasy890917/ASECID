package com.huaqin.ecidparser.telephony;

/**
 * Created by shiguibiao on 16-8-10.
 */

public interface LteInfoConstants {
    public static final String ATTR_NAME_VALUE = "value";
    public static final String ATTR_NAME_LTE_MODE = "ltemode";

    public static final String ELEMENT_NAME_LTE = "lte";

    public static final String PROPERTY_LTEREADY_VALUE = "Lteready@value";
    public static final String PROPERTY_LTEREADY_MODE = "Lteready@ltemode";

    public static final String LTEREADY_MODE_DB_NAME = "LG_ECID_LTEREADY_MODE";
    public static int MSG_UPDATE_LTE_MODE_INFO = 0;
}
