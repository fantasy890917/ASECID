
package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.amrwb.AmrwbParserAttribute;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;

public class AmrwbSettingParser extends GeneralProfileParser
		implements AmrwbParserAttribute {
	private static final String TAG = Utils.APP+AmrwbSettingParser.class.getSimpleName();



    public AmrwbSettingParser(Context context) {
		super(context);
	}

	protected ProfileData readProfile(XmlPullParser parser)
			throws XmlPullParserException, IOException {
		NameValueProfile p = new NameValueProfile();

		while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
				ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
			nextElement(parser);
		}

		while (ELEMENT_NAME_ITEM.equals(parser.getName())) {

			String tag = parser.getName();

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

    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data)
    {
		Log.d(TAG,"changeGpriValueFromLGE");
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put(KEY_ATTR_NAME_AMRWB_2G, ATTR_NAME_AMRWB_2G);
		matchmap.put(KEY_ATTR_NAME_AMRWB_3G, ATTR_NAME_AMRWB_3G);
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
