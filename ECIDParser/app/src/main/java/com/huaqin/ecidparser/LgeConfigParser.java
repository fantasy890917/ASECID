package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.utils.CAItem;
import com.huaqin.ecidparser.utils.GeneralParserAttribute;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Created by shiguibiao on 16-8-4.
 */

public class LgeConfigParser extends GeneralProfileParser {
    private static final String TAG = Utils.APP + LgeConfigParser.class.getSimpleName();
    private static boolean mXmlMatchingData = false;

    public LgeConfigParser(Context context) {
        super(context);

    }


    @Override
    protected ProfileData readProfile(XmlPullParser parser)
            throws XmlPullParserException, IOException {
        NameValueProfile p = new NameValueProfile();

        while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
                ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
            nextElement(parser);
        }
        Log.d(TAG,"readProfile---valid Element name="+parser.getName());
        while (parser.getName() != null
                &&(!parser.getName().equals(ELEMENT_NAME_PROFILE))) {

            String tag = parser.getName();
            Log.d(TAG, "[readProfile] TAG : " + tag);

            String key = parser.getName();
            if (key != null) {
                int type = parser.next();
                if (type == XmlPullParser.TEXT) {
                    String value = parser.getText();
                    p.setValue(key, value);
                    Log.d(TAG, "[readProfile] KEY : " + key + ", VALUE : " + value);
                }
            }
            nextElement(parser);
        }

        return (ProfileData)p;
    }

    @Override
    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data) {
        Log.d(TAG, "changeGpriValueFromLGE");
        HashMap<String, String> matchmap = new HashMap<String, String>();
        matchmap.put("Network@Data_Connection_Required", "enable_data_consumption_warning");
        matchmap.put("Network@Data_Connection_String", "sp_data_warning_noti_NORMAL");
        matchmap.put("Message@Voice_Mail_In_Home_Editable", "voice_mail_editable");
        matchmap.put("Settings@Connectivity_WiFi", "def_wifi_on");

        Iterator<String> key = matchmap.keySet().iterator();

        while (key.hasNext()) {
            String tag = key.next();
            String matchString_Value = (String) matchmap.get(tag);
            String value = ((NameValueProfile)data).getValue(matchString_Value);
            if (value != null) {
                hashmap.put(tag, value);
            }
        }
    }

}
