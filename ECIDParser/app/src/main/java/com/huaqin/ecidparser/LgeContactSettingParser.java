
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

public class LgeContactSettingParser extends GeneralProfileParser {
	private static final String TAG = Utils.APP+LgeContactSettingParser.class.getSimpleName();


   
    public LgeContactSettingParser(Context context) {
		super(context);
	}

	protected ProfileData readProfile(XmlPullParser parser)
			throws XmlPullParserException, IOException {
		NameValueProfile p = new NameValueProfile();
		int type;
		Log.d(TAG,"readProfile---name="+parser.getName()+" text="+parser.getText());
		while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
				ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
			nextElement(parser);
		}

		while (ELEMENT_NAME_ITEM.equals(parser.getName())) {

			String tag = parser.getName();

			String key = parser.getAttributeValue(null, ATTR_NAME);
			Log.d(TAG, "[readProfile] key : " + key);
			if (key != null) {
				type = parser.next();
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
        matchmap.put("Phonebook@Default_Storage_Location", "NEW_CONTACT_DEFAULT");
        matchmap.put("Phonebook@Display_the_numbers_on_phonebook", "display_number_on_phonebook");
        matchmap.put("Phonebook@Display_dialed_SDN_in_the_call_register", "display_SDN_in_call_register");
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
