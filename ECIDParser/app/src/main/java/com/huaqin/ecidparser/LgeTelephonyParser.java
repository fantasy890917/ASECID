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

public class LgeTelephonyParser extends GeneralProfileParser {

	public LgeTelephonyParser(Context context) {
		super(context);
		
	}

	@Override
	public ProfileData getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map ) {

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
