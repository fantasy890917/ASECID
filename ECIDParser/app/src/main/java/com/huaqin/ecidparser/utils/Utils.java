package com.huaqin.ecidparser.utils;
import android.util.Log;

import org.xmlpull.v1.XmlPullParser;

/**
 * Created by shiguibiao on 16-8-3.
 */

public class Utils {

    public static final String APP = "HQ-ECID";
    public static final String DEFAULT= "default";
    public static int MATCH_PRIORITY_OPERATOR_DEFAULT = 0;



    public static int getMatchPriority(XmlPullParser parser, LgeMccMncSimInfo simInfo,
                                         CAItem caItem){
        int  match_priority  = -1;
        boolean match_siminfo = false;
        String tempOperator = "";
        String tempCountry = "";
        String tempMcc = null;
        String tempMnc = null;
        String tempSpn = "";
        String tempImsi = "";
        String tempGid = "";
        boolean bAppendMode = false;
        boolean match_default = false;
        boolean isGidNull = true;
        boolean isSpnNull = true;
        boolean isImsiNull = true;

        String pars="";
        int AttributeNum = parser.getAttributeCount();
        for (int i = 0; i < AttributeNum; i++) {
            pars+=" "+parser.getAttributeName(i)+":"+parser.getAttributeValue(i);
            if ( parser.getAttributeName(i).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_OPERATOR) ) {
                tempOperator = parser.getAttributeValue(i);
            } else if ( parser.getAttributeName(i).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_COUNTRY) ) {
                tempCountry = parser.getAttributeValue(i);
            } else if ( parser.getAttributeName(i).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_MCC) ) {
                tempMcc = parser.getAttributeValue(i);
            } else if ( parser.getAttributeName(i).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_MNC) ) {
                tempMnc = parser.getAttributeValue(i);
            } else if (parser.getAttributeName(i).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_SPN)) {
                tempSpn = parser.getAttributeValue(i);
                if(tempSpn !=null
                        && tempSpn.length()>0){
                    isSpnNull =  false;
                    //Log.d(Utils.APP, "tempSpn not null");
                }
            } else if (parser.getAttributeName(i).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_GID)) {
                tempGid = parser.getAttributeValue(i);
                if(tempGid !=null
                        && tempGid.length()>0){
                    isGidNull =  false;
                    //Log.d(Utils.APP, "tempGid not null");
                }
                tempGid = GetParsingGidValue(simInfo.getGid(), parser.getAttributeValue(i));
            } else if (parser.getAttributeName(i).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_IMSI_RANGE)) {
                tempImsi = parser.getAttributeValue(i);
                if(tempImsi !=null
                        && tempImsi.length()>0){
                    isImsiNull =  false;
                    //Log.d(Utils.APP, "tempImsi not null");
                }
                tempImsi = GetParsingImsiValue(simInfo.getImsi(), parser.getAttributeValue(i));
            }
        }
        //Log.d(Utils.APP, "tempMcc = "+tempMcc+" tempMnc= "+tempMnc+" tempSpn= "+tempSpn+" tempGid= "+tempGid+" tempImsi= "+tempImsi);
        if (AttributeNum == 1
                && parser.getAttributeName(0).equalsIgnoreCase(SIMInfoConstants.ATTR_NAME_DEFAULT)
                && parser.getAttributeValue(0).equals("true"))  {
            if (!bAppendMode) {
                caItem.clearSettingItem();
            }
            Log.d(Utils.APP, "siminfo default=true");
            match_priority = 0;
            match_siminfo = true;
        }else if(tempOperator.equals(DEFAULT)){
            Log.d(Utils.APP, "siminfo operator=default");
            match_priority = 0;
            match_siminfo = true;
        }

        //for mccmnc only
        if (AttributeNum == 4 && simInfo.getMcc().equals(tempMcc)
                && simInfo.getMnc().equals(tempMnc)
                && ( match_priority == -1) )  {
            caItem.mOperator  = tempOperator;
            caItem.mCountry = tempCountry;

            caItem.mMcc = tempMcc;
            caItem.mMnc = tempMnc;
            if (!bAppendMode) {
                caItem.clearSettingItem();
            }
            match_priority = 1;
        }

        //for
        if(AttributeNum >=5
                && simInfo.getMcc().equals(tempMcc)
                && simInfo.getMnc().equals(tempMnc)
                && ( match_priority == -1) ){
            Log.d(Utils.APP, "result:"+pars);
            Log.d(Utils.APP, "test for lteready,match mccmnc");
            if(isGidNull && isImsiNull && isSpnNull){
                match_priority = 1;
                Log.d(Utils.APP, "for lteready,match mccmnc");
            }

        }
        if (AttributeNum >= 5  &&
                simInfo.getMcc().equals(tempMcc)
                && simInfo.getMnc().equals(tempMnc) ) {

            if ((tempSpn != null)
                     && (simInfo.getSpn() != null)
                     && simInfo.getSpn().equals(tempSpn) ) {
                caItem.mOperator  = tempOperator;
                caItem.mCountry = tempCountry;
                caItem.mMcc = tempMcc;
                caItem.mMnc = tempMnc;
                caItem.mSpn = tempSpn;
                if (!bAppendMode) {
                    caItem.clearSettingItem();
                }

                match_siminfo = true;
                match_priority++;
            }

            if ((tempGid != null)
                    && (simInfo.getGid() != null)
                    && simInfo.getGid().toUpperCase().contains(tempGid.toUpperCase())) {
                caItem.mOperator  = tempOperator;
                caItem.mCountry = tempCountry;
                caItem.mMcc = tempMcc;
                caItem.mMnc = tempMnc;
                caItem.mGid = tempGid;
                if (!bAppendMode) {
                    caItem.clearSettingItem();
                }

                match_siminfo = true;
                match_priority++;
            }

            if ((tempImsi != null)
                    && (simInfo.getImsi() !=null)
                    && simInfo.getImsi().equals(tempImsi) ) {
                caItem.mOperator  = tempOperator;
                caItem.mCountry = tempCountry;
                caItem.mMcc = tempMcc;
                caItem.mMnc	= tempMnc;
                caItem.mImsi	= tempImsi;
                if (!bAppendMode) {
                    caItem.clearSettingItem();
                }
                match_siminfo = true;
                match_priority++;
            }

        }
        return match_priority;
    }

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
}
