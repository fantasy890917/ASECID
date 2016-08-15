package com.huaqin.ecidparser.telephony;

/**
 * Created by shiguibiao on 16-8-14.
 */

public interface TelephonyParserAttribute {
    public static final String ATTR_NAME_VALUE = "value";
    public static final String ATTR_NAME_LTE_MODE = "ltemode";

    public static final String ELEMENT_NAME_LTE = "lte";

    public static final String KEY_LTEREADY_VALUE = "Lteready@value";
    public static final String KEY_LTEREADY_MODE = "Lteready@ltemode";

    /*
    <item name="VMS">123</item>
    <item name="RVMS">+262692069200</item>
    <item name="ECC_list">101</item>
    <item name="ECC_IdleMode">199,1400,1441</item>
    <item name="HOME_NETWORK">64710,20809</item>
    <item name="sim_lock_ecclist">060</item>
    <item name="TBCW">true</item>
    <item name="FULL_TBCW">true</item>
    <item name="ShortCodeCall">#9,*228</item>
    <item name="SRVCC_Support">1</item>
    <item name="aSRVCC">1</item>
    <item name="eSRVCC">1</item>
    <item name="MidCall_SRVCC">1</item>
    */
}
