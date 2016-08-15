package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;

public class LgeTelephonyParser extends GeneralProfileParser {

	private static final String TAG = Utils.APP+LgeTelephonyParser.class.getSimpleName();
	public LgeTelephonyParser(Context context) {
		super(context);
		
	}

	@Override
	protected ProfileData readProfile(XmlPullParser parser)
			throws XmlPullParserException, IOException {
		NameValueProfile p = new NameValueProfile();
		Log.d(TAG,"[readProfile] name="+parser.getName());
		while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
				ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
			nextElement(parser);
		}

		while (parser.getName() != null
				&&(!parser.getName().equals(ELEMENT_NAME_PROFILE))) {

			String tag = parser.getName();
			Log.d(TAG, "[readProfile] TAG : " + tag);
			String key = parser.getAttributeValue(null, ATTR_NAME);
			Log.d(TAG, "[readProfile] key : " + key);
			if (key != null) {
				int type = parser.next();
				Log.d(TAG, "[readProfile] type : " + type);
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
    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data)
    {
		Log.d(TAG,"changeGpriValueFromLGE");
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put("Network@Short_Call_Code_Short_Number", "ShortCodeCall");
        matchmap.put("Message@Voice_Mail_In_Home_Number", "VMS");
        matchmap.put("Message@Voice_Mail_In_Roaming_Number", "RVMS");
        matchmap.put("Network@Emergency_Numbers_Additional_numbers_With_SIM_Card", "ECC_list");
        matchmap.put("Network@Short_Call_Code_Short_Emergency_Number", "ECC_IdleMode");

        Iterator<String> key = matchmap.keySet().iterator(); 
        
        while(key.hasNext()) 
        {
            String tag = key.next();
            String matchString_Value = (String) matchmap.get(tag);
            String value = ((NameValueProfile)data).getValue(matchString_Value);
            if (value != null) 
            {
                hashmap.put(tag, value);
            }
        }
    }
}
