package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;

public class LgeMmsConfigParser extends GeneralProfileParser {

    private static final String TAG = Utils.APP+LgeMmsConfigParser.class.getSimpleName();
    public LgeMmsConfigParser(Context context) {
        super(context);
    }

    @Override
    protected ProfileData readProfile(XmlPullParser parser)
            throws XmlPullParserException, IOException {
        Log.d(TAG,"readProfile-----------------");
        NameValueProfile p = new NameValueProfile();
        int type;
        Log.d(TAG,"readProfile---name="+parser.getName()+" text="+parser.getText());
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
                type = parser.next();
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
        Log.d(TAG,"changeGpriValueFromLGE");
        HashMap<String, String> matchmap = new HashMap<String, String>();
        matchmap.put("Message@SMS_Delivery_Report", "sms_dr");
        matchmap.put("Message@SMS_Number", "smsc");
        matchmap.put("Message@SMS_Editable", "smsc_readonly");
        matchmap.put("Message@SMS_Unicode_characters", "sms_char");
        //matchmap.put("Message@Cell_Broadcast_Receive", "sms_sent_time_mode");
        matchmap.put("Message@SMS_Validity_Period", "sms_validity");
        matchmap.put("Message@SMS_Turn_to_MMS_when_SMS_size_is_more_than", "sms_concat");
        matchmap.put("Message@MMS_Report_Request", "mms_dr_r");
        matchmap.put("Message@SMS_Remove_SMS_templates", "sms_templates_removable");

        matchmap.put("Message@MMS_Allow_Report", "mms_dr_a");
        matchmap.put("Message@MMS_Request_reply", "mms_rr_r");
        matchmap.put("Message@MMS_Allow_reply", "mms_rr_a");
        matchmap.put("Message@MMS_Home", "auto_retr");
        matchmap.put("Message@MMS_Roaming", "auto_retr_r");
        matchmap.put("Message@MMS_MMS_Priority", "mms_priority");
        matchmap.put("Message@MMS_Validity_period", "mms_validity");
        matchmap.put("Message@MMS_Maximum_Size", "mms_size");

        matchmap.put("Message@MMS_Creation_mode", "mms_creation");
        matchmap.put("Message@MMS_Slide_Duration_(in_seconds)", "slide_dur");
        matchmap.put("Message@MMS_Advertisement", "recv_adv");
        matchmap.put("Message@Cell_Broadcast_Receive", "cb_on");
        matchmap.put("Internet@Receive_push_message", "push_on");
        //matchmap.put("Message@MMS_Maximum_Size", "del_old");

        Iterator<String> key = matchmap.keySet().iterator();

        while (key.hasNext()) {
            String tag = key.next();
            String matchString_Value = (String) matchmap.get(tag);
            String value = ((NameValueProfile)data).getValue(matchString_Value);
            if (value != null) {
                Log.d(TAG,"match:"+matchString_Value+" value:"+value);
                if ("smsc_readonly".equals(matchString_Value)) {
                    value = "1".equals(value) ? "0" : "1";
                }
                hashmap.put(tag, value);
            }
        }
    }

}


