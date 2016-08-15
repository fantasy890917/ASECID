package com.huaqin.ecidparser;

import android.content.Context;
import android.provider.Settings;
import android.util.Log;

import com.huaqin.ecidparser.telephony.TelephonyParserAttribute;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.HashMap;
import java.util.Iterator;
public class LgeLTEConfigParser extends GeneralProfileParser
        implements TelephonyParserAttribute {
    private static final String TAG = Utils.APP+LgeLTEConfigParser.class.getSimpleName();
	public LgeLTEConfigParser(Context context) {
		super(context);
	}

    @Override
    protected ProfileData readProfile(XmlPullParser parser)
            throws XmlPullParserException, IOException {
        Log.d(TAG,"[readProfile]");
        NameValueProfile p = new NameValueProfile();
        String tempLteMode = parser.getAttributeValue(null,ATTR_NAME_LTE_MODE);
        String tempValue = parser.getAttributeValue(null,ATTR_NAME_VALUE);
        Log.d(TAG,"tempValue=="+tempValue);
        Log.d(TAG,"tempLteMode=="+tempLteMode);
        p.getValueMap().put(ATTR_NAME_LTE_MODE,tempLteMode);
        p.getValueMap().put(ATTR_NAME_VALUE,tempValue);
        nextElement(parser);

        return (ProfileData)p;
    }

    @Override
    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data){
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put(KEY_LTEREADY_VALUE, ATTR_NAME_VALUE);
        matchmap.put(KEY_LTEREADY_MODE,ATTR_NAME_LTE_MODE);

        Iterator<String> key = matchmap.keySet().iterator();

        while(key.hasNext())
        {
            String tag = key.next();
            String matchString_Value = (String) matchmap.get(tag);
            String value =((NameValueProfile)data).getValue(matchString_Value);
            if (value != null)
            {
                if(KEY_LTEREADY_MODE.equals(tag)){
                    Settings.System.putInt(mContext.getContentResolver(), KEY_LTEREADY_MODE,
                            value.equals("LTE") ? 1 : 0);
                }
                hashmap.put(tag, value);
            }
        }
    }


    protected void getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map) {

        Log.d(TAG, "getMatchedProfile");
        ProfileData commonProfile = null;
        int foundPriority = NO_MATCH;
        int currentMatch = NO_MATCH;
        MatchedProfile profile = new MatchedProfile();

        if (parser == null) {
            return;
        }

        try {
            // find a "<profiles>" element
            beginDocument(parser, ELEMENT_NAME_LTE);

            while (true) {
                if (DBG) {
                    Log.d(TAG, "FANTA GET TAG NAME:" + parser.getName());
                }

                if (parser.getEventType() == XmlPullParser.END_DOCUMENT) {
                    break;
                }
                // find a "<profiles>" element
                if (ELEMENT_NAME_LTE.equals(parser.getName())) {
                } else if (ELEMENT_NAME_PROFILE.equals(parser.getName())) {// find a "<profile>" element

                } else if (ELEMENT_NAME_SIMINFO.equals(parser.getName())) {// find a "<siminfo>" element
                    currentMatch = NO_MATCH;
                    foundPriority = getValidProfile(profile, parser, simInfo);
                    // test code , if sim info is null, use default profile (need to place default profile at the top of the profiles, the fastest way)
                    // when bestMatchedProfile was found
                    if (profile.mBestMatchedProfile != null) {
                        Log.v(TAG, "[getMatchedProfile] currentMatch : " + currentMatch + "bestMatchedProfile" + profile.mBestMatchedProfile);
                        break;
                    }

                    // we didn't parse this element
                    if (foundPriority != NO_MATCH) {
                        currentMatch = foundPriority;
                        Log.d(TAG, "[getMatchedProfile] MATCH");
                    }

                    if (currentMatch != NO_MATCH) {
                        if (currentMatch == FIND_DEFAULT_MATCH) {
                            profile.mDefaultProfile = readProfile(parser);
                        } else if (currentMatch == FIND_CANDIDATE_MATCH) {
                            if (profile.mCandidateProfile == null) {
                                profile.mCandidateProfile = readProfile(parser);
                            }
                        } else if (currentMatch == FIND_BEST_MATCH) {
                            profile.mBestMatchedProfile = readProfile(parser);
                        }
                        continue;
                    }
                } else if (ELEMENT_NAME_COMMONPROFILE.equals(parser.getName())) {
                    // find a "<CommonProfile>" element
                    commonProfile = readProfile(parser);
                } else {
                    throw new XmlPullParserException("Unexpected tag: found " + parser.getName());
                }
                nextElement(parser);
            }
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        mergeProfileIfNeed(profile, commonProfile, map);
    }

}


