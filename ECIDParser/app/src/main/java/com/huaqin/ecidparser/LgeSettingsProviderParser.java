package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;


public class LgeSettingsProviderParser extends GeneralProfileParser {


	public LgeSettingsProviderParser(Context context) {
		super(context);

	}

	@Override
	public ProfileData getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map ) {

		ProfileData commonProfile = null;
		ProfileData validProfile = null;
		ProfileData featureProfile = null;
		boolean found = false;
		MatchedProfile profile = new MatchedProfile();

		if (parser == null) {
			return null;
		}

		try {
			// find a "<profiles>" element
			beginDocument(parser, ELEMENT_NAME_PROFILES);

			while (true) {
				// find a "<profiles>" element
				if (ELEMENT_NAME_PROFILES.equals(parser.getName())) {
					nextElement(parser);
				}
				// find a "<profile>" element
				if (ELEMENT_NAME_PROFILE.equals(parser.getName())) {
					nextElement(parser);    // find a "<siminfo>" element or <FeatureSet>
				}
				if (parser.getEventType() == XmlPullParser.END_DOCUMENT) {
					break;
				}
				// find a "<siminfo>" element
				if (ELEMENT_NAME_SIMINFO.equals(parser.getName())) {

					found = getValidProfile(profile, parser, simInfo);

					// test code , if sim info is null, use default profile (need to place default profile at the top of the profiles, the fastest way)
					// when bestMatchedProfile was found
					if (((simInfo == null || simInfo.isNull()) && profile.mDefaultProfile != null) || profile.mBestMatchedProfile != null) {
						if (VDBG) {
							Log.v(TAG, "[getMatchedProfile] sim info : " + simInfo + "bestMatchedProfile" + profile.mBestMatchedProfile);
						}
						break;
					}

					// we didn't parse this element
					if (!found) {
						skipCurrentElement(parser);

						if (DBG) { Log.d(TAG, "[getMatchedProfile] skipCurrentElement"); }
					}
				} 
			}
		} catch (XmlPullParserException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		validProfile = profile.mBestMatchedProfile != null ? profile.mBestMatchedProfile :
			profile.mCandidateProfile != null ? profile.mCandidateProfile : profile.mDefaultProfile;

		return mergeProfileIfNeeded(commonProfile, validProfile, featureProfile, map);

	}

    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data)
    {
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
		while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) || ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
			nextElement(parser);
		}

		while (ELEMENT_NAME_SYSTEMPROPERTY.equals(parser.getName()) 
				|| ELEMENT_NAME_SETTINGSSYSTEM.equals(parser.getName())
				|| ELEMENT_NAME_SETTINGSSECURE.equals(parser.getName()) ) {

			String tag = parser.getName();
			if (DBG) {
				Log.d(TAG, "[readProfile] TAG : " + tag);
			}
			
			int AttributeNum = parser.getAttributeCount();
			
			for (int i = 0; i < AttributeNum; i++) {

				if (parser.getName() != null){
					p.setValue(parser.getAttributeName(i), parser.getAttributeValue(i));
				}
			}
			nextElement(parser);

			

		}
		return (ProfileData)p;
	}
}

	



