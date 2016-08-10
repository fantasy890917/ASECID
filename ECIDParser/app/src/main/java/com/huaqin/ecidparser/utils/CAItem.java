package com.huaqin.ecidparser.utils;

import android.util.Log;

import java.util.HashMap;

/**
 * Created by shiguibiao on 16-8-3.
 */

public class CAItem extends ProfileData {

    private static final String TAG = "MmsSettings";
    private static final boolean DEBUG = true;


    public String mOperator;
    public String mCountry;
    public String mMnc;
    public String mMcc;
    public String mSpn;
    public String mGid;
    public String mImsi;
    public HashMap<String, String> mSettingItems;

    public static class SettingItem {
        public String id;
        public String value;

        SettingItem( String pId, String pValue ) {
            id = pId;
            value = pValue;
        }
    }

    public CAItem() {
        mSettingItems = new HashMap<String, String>();

    }

    public HashMap<String, String>  getSettingItems() {
        return mSettingItems;
    }

    public void addSettingItem( String id, String value ) {
        if ( id != null && value != null ) {
            mSettingItems.put(id, value);
        }
    }

    public void clearSettingItem() {
        mSettingItems.clear();
    }

    public HashMap<String, String> getValueMap(){
        return mSettingItems;
    }


    public void print() {
        if (DEBUG) {
            Log.d( TAG, "[LGE]---------------------------------------->");
            //        	if (MmsConfig.PRIVACY_ENABLE) {
            Log.d( TAG, "[LGE]   Op = [" + mOperator + "]");
            Log.d( TAG, "[LGE]   Co = [" + mCountry + "]");
            Log.d( TAG, "[LGE]   Mnc = [" + mMnc + "]");
            Log.d( TAG, "[LGE]   Mcc = [" + mMcc + "]");
            Log.d( TAG, "[LGE]   Spn = [" + mSpn + "]");
            Log.d( TAG, "[LGE]   Gid = [" + mGid + "]");
            Log.d( TAG, "[LGE]   Imsi = [" + mImsi + "]");
            //        	}
        }

    }
}
