
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
public class LgeContactSettingParser extends GeneralProfileParser {

    public static final String ATTR_ITEM_STORAGE = "NEW_CONTACT_DEFAULT";
    public static final String ATTR_VALUE_SIM_STORAGE = "In SIM memory";
    public static final String ATTR_VALUE_GOOGLE_STORAGE = "In Google memory";
    public static final String KEY_PREFER_DEFAULT_ACCOUNT = "default_account";
    public static final String SIM_ACCOUNT = "sim";
    public static final String GOOGLE_ACCOUNT = "google";
    public static final String PHONE_ACCOUNT = "phone";

   
    public LgeContactSettingParser(Context context) {
		super(context);
	}
   

    @Override
	protected ProfileData getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map) {

                Log.d(TAG, "LgeContactSettingParser-getMatchedProfile");
		ProfileData commonProfile = null;
		ProfileData validProfile = null;
		ProfileData featureProfile = null;
		boolean found;
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
				// find a "<profiles>" element
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
					if (((simInfo == null || simInfo.isNull())
							&& profile.mDefaultProfile != null)
							|| profile.mBestMatchedProfile != null) {
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

				// find a "<CommonProfile>" element 
				else if (ELEMENT_NAME_COMMONPROFILE.equals(parser.getName())) {
					commonProfile = readProfile(parser);
				} 
				else {
					throw new XmlPullParserException("Unexpected tag: found " + parser.getName());
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
