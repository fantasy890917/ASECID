package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;
import com.huaqin.ecidparser.utils.Utils;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
import com.huaqin.ecidparser.settings.SettingsParserAttribute;

public class LgeSettingsProviderParser
		extends GeneralProfileParser
		implements SettingsParserAttribute{
	private static final String TAG = Utils.APP+LgeSettingsProviderParser.class.getSimpleName();

	public LgeSettingsProviderParser(Context context) {
		super(context);

	}



    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data)
    {
		Log.d(TAG,"changeGpriValueFromLGE");
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put("Settings@Phone_Time_Format", "time_12_24");
        matchmap.put("Settings@Phone_Auto_update_date/time", "auto_time");
        matchmap.put("Settings@Display_Backlight", "screen_off_timeout");
        matchmap.put("Settings@Profile_Sound_Keypad_tone", "dtmf_tone_when_dialing");
        matchmap.put("Settings@Profile_Sound_Touch_Tone", "sound_effects_enabled");
        matchmap.put("Settings@Connectivity_Data_connection", "mobile_data");
        matchmap.put("Settings@Connectivity_Data_connection_in_roaming", "data_roaming");
        matchmap.put("Settings@Phone_Time_Zone", "default_timezone");
        matchmap.put("Settings@Phone_Default_Language_With_SIM_Card_#1", "default_language");
        matchmap.put("Settings@Phone_Default_GPS_activation", "location_providers_allowed");
        //matchmap.put(" ", "install_non_market_apps");
        matchmap.put("Settings@Profile_Sound_Vibrate_ON/OFF", "sound_profile");
        matchmap.put("Settings@Profile_Sound_Notification_vibrate", "notification_vibrate");
        matchmap.put("Settings@Profile_Sound_Ringtone_with_Vibration", "ringtone_vibration");
        matchmap.put("Settings@Phone_Date_Format", "def_date_format");


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

	@Override
	protected ProfileData readProfile(XmlPullParser parser) throws XmlPullParserException, IOException {


		NameValueProfile p = new NameValueProfile();
		while (ELEMENT_NAME_SIMINFO.equals(parser.getName())
				|| ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
			nextElement(parser);
		}

		while (ELEMENT_NAME_SYSTEMPROPERTY.equals(parser.getName()) 
				|| ELEMENT_NAME_SETTINGSSYSTEM.equals(parser.getName())
				|| ELEMENT_NAME_SETTINGSSECURE.equals(parser.getName()) ) {

			String tag = parser.getName();
			if (true) {
				Log.d(TAG, "[readProfile] TAG : " + tag);
			}
			
			int AttributeNum = parser.getAttributeCount();
			
			for (int i = 0; i < AttributeNum; i++) {
				String key = parser.getAttributeName(i);
				String value = parser.getAttributeValue(i);
				Log.d(TAG,"[readProfile] Key : "+key+" value:"+value);
				if((!Utils.isEmpty(key))
						&& (!Utils.isEmpty(value))){
					p.setValue(key,value);
				}
			}
			nextElement(parser);

		}
		return (ProfileData)p;
	}
}

	



