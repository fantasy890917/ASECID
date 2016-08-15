package com.huaqin.ecidparser.utils;
/**
 * Created by shiguibiao on 16-8-3.
 */

public class Utils {

    public static final String APP = "[HQ-ECID]";
    public static final String DEFAULT= "default";
    public static String GetParsingImsiValue(String CurrentImsi, String temp_imsi) {
        boolean math_imsi = true;
        int GidValue_ChkNum;

        if (CurrentImsi == null){
            CurrentImsi = DEFAULT;
        }

        if (CurrentImsi.length() >=  temp_imsi.length()) {
            GidValue_ChkNum = temp_imsi.length();
        } else {
            GidValue_ChkNum = CurrentImsi.length();
        }

        for ( int i = 0; i < GidValue_ChkNum; i++ ) {
            if (temp_imsi.charAt(i) == 'x') {
                continue;
            } else if (CurrentImsi.charAt(i) != temp_imsi.charAt(i)) {
                math_imsi = false;
                break;
            }
        }

        if (math_imsi) {
            return CurrentImsi;
        } else {
            return temp_imsi;
        }
    }

    public static String GetParsingGidValue(String CurrentGid, String temp_gid) {
        boolean math_gid = true;
        int GidValue_ChkNum;

        if (CurrentGid == null){
            CurrentGid = DEFAULT;
        }

        if (CurrentGid.length() >=  temp_gid.length()) {
            GidValue_ChkNum = temp_gid.length();
        } else {
            GidValue_ChkNum = CurrentGid.length();
        }

        for (int i = 0; i < GidValue_ChkNum; i++) {
            if (CurrentGid.charAt(i) !=  temp_gid.charAt(i)) {
                math_gid = false;
                break;
            }
        }

        if (math_gid) {
            return CurrentGid;
        } else {
            return temp_gid;
        }
    }

    public static boolean isEmpty(String string){
        return string ==null || string.isEmpty();
    }
}
