package com.huaqin.ecidparser;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;

import com.huaqin.ecidparser.utils.GeneralParserAttribute;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.SIMInfoConstants;
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
import java.util.Set;

/**
 * Created by shiguibiao on 16-8-4.
 */

public class GeneralProfileParser implements GeneralParserAttribute {

    public static final String TAG = Utils.APP;
    public static final boolean DBG = false;
    public static final boolean VDBG = false;

    public Context mContext;
    public FileReader in = null;
    public XmlPullParserFactory factory;
    public XmlPullParser parser = null;

    public static int mPhoneId = 0;

    public GeneralProfileParser(Context context) {
        mContext = context;

    }


    public class MatchedProfile {
        public ProfileData mBestMatchedProfile;
        public ProfileData mCandidateProfile;
        public ProfileData mDefaultProfile;

        public MatchedProfile() {
            mDefaultProfile = null;
            mCandidateProfile = null;
            mBestMatchedProfile = null;
        }

    }

    public static class NameValueProfile extends ProfileData {
        public HashMap<String, String> mNameValueMap = new HashMap<String, String>();

        public void setValue(String key, String value) {
            mNameValueMap.put(key, value);
        }

        public String getValue(String key) {
            return mNameValueMap.get(key);
        }

        public String getValue(String key, String defaultValue) {
            if (!mNameValueMap.containsKey(key)) {
                return defaultValue;
            }

            return mNameValueMap.get(key);
        }

        public void remove(String key) {
            mNameValueMap.remove(key);
        }


        public HashMap<String, String> getValueMap() {
            return mNameValueMap;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();

            Set<String> set = mNameValueMap.keySet();
            Iterator<String> keys = set.iterator();

            while (keys.hasNext()) {
                String key = keys.next();
                sb.append(key + "=" + mNameValueMap.get(key) + "\n");
            }


            if (sb == null) {
                return null;
            }

            return sb.toString();
        }
    }


    /**
     * This method will be called when needs to merge commonProfile and matchedProfile
     *
     * @param commonProfile  which has default attribute
     * @param matchedProfile matched
     * @return The ProfileData merged
     */
//<2015/12/15-junam.hwang, [D5][PORTING][COMMON][FLEX2][][] modify the gpri mapping
    protected void mergeProfile(ProfileData commonProfile, ProfileData matchedProfile,
                                HashMap<String, String> map) {
        Log.d(TAG, "------------------mergeProfile-----------------");
        if (matchedProfile == null) {
            return;
        }
        NameValueProfile cp = (NameValueProfile) commonProfile;
        NameValueProfile mp = (NameValueProfile) matchedProfile;

        Set<String> set;
        Iterator<String> keys;

        if (cp != null) {
            // Set Common Profile
            set = cp.mNameValueMap.keySet();
            keys = set.iterator();

            while (keys.hasNext()) {
                String key = keys.next();
                if (!mp.mNameValueMap.containsKey(key)) {
                    mp.mNameValueMap.put(key, cp.getValue(key));
                }
            }
        }
        Log.d(TAG, "----------------need changeGpriValueFromLGE-----------------");
        changeGpriValueFromLGE(map, mp);
    }


    public int getValidProfile(MatchedProfile profile, XmlPullParser parser, LgeMccMncSimInfo simInfo) {
        String mccValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_MCC);
        String mncValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_MNC);
        String operatorValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_OPERATOR);
        String countryValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_COUNTRY);
        String gidValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_GID);
        String spnValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_SPN);
        String imsiValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_IMSI_RANGE);
        if (DBG) {
            Log.d(TAG, "[test------------] TAG : " + parser.getName() + " MCC : "
                    + mccValue + " MNC :" + mncValue + " GID :" + gidValue
                    + " SPN :" + spnValue + " IMSI:" + imsiValue);
        }
        boolean isDefault = "true".equals(parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_DEFAULT));

        if (isDefault) {
            Log.d(TAG, "MATCH DEFAULT");
            return FIND_DEFAULT_MATCH;
        }


        if (matchMccMnc(simInfo, mccValue, mncValue)) {

            // keep the first mccmnc matched profile.
            // input value to candidateProfile in case of no gid, spn & imsi
            if (profile.mCandidateProfile == null && Utils.isEmpty(gidValue) && Utils.isEmpty(spnValue) && Utils.isEmpty(imsiValue)) {
                Log.d(TAG, "[MATCH MCCMNC");
                Log.d(TAG, "[getValidProfile] TAG : " + parser.getName());
                Log.d(TAG, "[getValidProfile] MCC : " + mccValue);
                Log.d(TAG, "[getValidProfile] MNC : " + mncValue);
                Log.d(TAG, "[getValidProfile] OPERATOR : " + operatorValue);
                Log.d(TAG, "[getValidProfile] COUNTRY : " + countryValue);
                return FIND_CANDIDATE_MATCH;
            }

            if (profile.mBestMatchedProfile == null && (!Utils.isEmpty(gidValue) || !Utils.isEmpty(spnValue) || !Utils.isEmpty(imsiValue))) {

                if (matchExtension(simInfo, gidValue, spnValue, imsiValue)) {
                    Log.d(TAG, "[MATCH gid/spn/imsi");
                    Log.d(TAG, "[getValidProfile] TAG : " + parser.getName());
                    Log.d(TAG, "[getValidProfile] MCC : " + mccValue);
                    Log.d(TAG, "[getValidProfile] MNC : " + mncValue);
                    Log.d(TAG, "[getValidProfile] OPERATOR : " + operatorValue);
                    Log.d(TAG, "[getValidProfile] COUNTRY : " + countryValue);
                    Log.d(TAG, "[getValidProfile] GID : " + gidValue);
                    Log.d(TAG, "[getValidProfile] SPN : " + spnValue);
                    Log.d(TAG, "[getValidProfile] IMSI : " + imsiValue);
                    return FIND_BEST_MATCH;

                }

            }
        }

        return NO_MATCH;
    }

    /**
     * This method will be called whenever the parser meets &lt;Profile&gt;
     *
     * @param parser XmlPullParser
     * @return The ProfileData object
     */
    protected ProfileData readProfile(XmlPullParser parser)
            throws XmlPullParserException, IOException {
        return null;
    }

    //should be override
    protected boolean currentElemntShouldBeSkiped(XmlPullParser parser) {
        return ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
                ELEMENT_NAME_FEATURESET.equals(parser.getName());
    }


    protected boolean matchExtension(LgeMccMncSimInfo simInfo, String gidParsed, String spnParsed, String imsiParsed) {
        if (simInfo == null) {
            return false;
        }
        String gid = simInfo.getGid();
        String spn = simInfo.getSpn();
        String imsi = simInfo.getImsi();

        if (Utils.isEmpty(gid) && Utils.isEmpty(spn) && Utils.isEmpty(imsi)) {
            return false;
        }

        if (!Utils.isEmpty(gid) && gidParsed != null) {
            int gidLength = gid.length();
            if ("ff".equals(gid) || "00".equals(gid)) {
                if (DBG) {
                    Log.d(TAG, "[matchExtension] invalid gid" + gid);
                }
                return false;
            } else if (existInTokens(gidParsed, gid, gidLength)) {
                if (DBG) {
                    Log.d(TAG, "[matchExtension] match gid");
                }
                return true;
            }
        }

        if (spn != null && spnParsed != null) {
            if (spnParsed.equalsIgnoreCase(spn)) {
                if (DBG) {
                    Log.d(TAG, "[matchExtension] match spn");
                }
                return true;
            }
        }

        if (imsi != null && imsiParsed != null && imsiParsed.length() != 0) {
            if (matchImsi(imsiParsed, imsi)) {
                if (DBG) {
                    Log.d(TAG, "[matchExtension] match imsi");
                }
                return true;
            }
        }

        if (DBG) {
            Log.v(TAG, "[matchExtension] true");
        }
        return false;
    }

    /*[LGSI-TELEPHONY][sarmistha.pani][TD342174 Contact apk crash][05.06.2013][START]
     * Contacts Apk crash due to Null exception while accessing Imsi length in profileParser . At this point IMSI is null
     */
    protected boolean matchImsi(String imsiParsed, String imsi) {
        boolean match_imsi = true;
        int length;

        if (imsi.length() >= imsiParsed.length()) {
            length = imsiParsed.length();
        } else {
            length = imsi.length();
        }

        for (int i = 0; i < length; i++) {
            if (imsi.charAt(i) == 'x') {
                continue;
            } else if (imsi.charAt(i) != imsiParsed.charAt(i)) {
                match_imsi = false;
                break;
            }
        }

        return match_imsi;
    }


    protected boolean existInTokens(String string, String v, int len) {
        if (string == null || v == null) {
            return false;
        }

        int xml_length = string.length();
        int final_length;

        if (xml_length > len) {
            final_length = len;
        } else {
            final_length = xml_length;
        }

        if (DBG) {
            Log.d(TAG, "[existInTokens] final length : " + final_length);
        }

        String fixed_xml_gid = string.substring(0, final_length);
        String fixed_sim_gid = v.substring(0, final_length);

        if (fixed_xml_gid.equalsIgnoreCase(fixed_sim_gid)) {
            return true;
        }

        return false;
    }

    protected boolean matchMccMnc(LgeMccMncSimInfo simInfo, String mccParsed, String mncParsed) {
        if (simInfo != null) {
            String mcc = simInfo.getMcc();
            String mnc = simInfo.getMnc();

            if (!TextUtils.isEmpty(mcc) && !TextUtils.isEmpty(mnc)) {
                if (mcc.equals(mccParsed) && mnc.equals(mncParsed)) {
                    //if (TextUtils.equals(mcc, mccParsed) && TextUtils.equals(mnc, mncParsed)) {
                    if (DBG) {
                        Log.d(TAG, "[matchMccMnc] true");
                    }
                    return true;
                }
            }
        }
        if (DBG) {
            Log.d(TAG, "[matchMccMnc] false");
        }

        return false;
    }


    protected final void beginDocument(XmlPullParser parser, String firstElementName)
            throws XmlPullParserException, IOException {
        int type = parser.next();
        String name = parser.getName();
        if (type != XmlPullParser.START_TAG) {
            throw new XmlPullParserException("No start tag found");
        }

        if (!firstElementName.equals(name)) {
            throw new XmlPullParserException("Unexpected start tag: found " + name + ", expected "
                    + firstElementName);
        }
    }

    protected final void nextElement(XmlPullParser parser)
            throws XmlPullParserException, IOException {
        int type;
        while ((type = parser.next()) != XmlPullParser.START_TAG && type != XmlPullParser.END_DOCUMENT) {
            ;   // do nothing
        }
    }

    /**
     * Gets a matched profile from a XmlPullParser
     *
     * @param parser  XmlPullParser object
     * @param simInfo The SIM card information
     * @param map     add to preference  eunheon.kim
     * @return The ProfileData object matched
     */
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
            beginDocument(parser, ELEMENT_NAME_PROFILES);

            while (true) {
                if (DBG) {
                    Log.d(TAG, "FANTA GET TAG NAME:" + parser.getName());
                }

                if (parser.getEventType() == XmlPullParser.END_DOCUMENT) {
                    break;
                }
                // find a "<profiles>" element
                if (ELEMENT_NAME_PROFILES.equals(parser.getName())) {
                } else if (ELEMENT_NAME_PROFILE.equals(parser.getName())) {// find a "<profile>" element
                    currentMatch = NO_MATCH;
                } else if (ELEMENT_NAME_SIMINFO.equals(parser.getName())) {// find a "<siminfo>" element
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
                } else if (ELEMENT_NAME_COMMONPROFILE.equals(parser.getName())) {
                    // find a "<CommonProfile>" element
                    commonProfile = readProfile(parser);
                } else if (parser.getName() != null) {
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

    protected void mergeProfileIfNeed(MatchedProfile profile, ProfileData commonProfile,
                                      HashMap<String, String> map) {
        Log.d(TAG, "------------------mergeProfileIfNeed-----------------");
        ProfileData validProfile = null;
        validProfile = profile.mBestMatchedProfile != null ? profile.mBestMatchedProfile :
                profile.mCandidateProfile != null ? profile.mCandidateProfile : profile.mDefaultProfile;
        if (profile.mDefaultProfile != null
                && (profile.mCandidateProfile != null || profile.mBestMatchedProfile != null)) {
            //for CLR COM telephony.xml if has default attr no_sim_card ,but candidate and best
            //has no it , so default need merge with candidate or best.
            Log.d(TAG, "merge default with condidate or best");
            NameValueProfile defualt = (NameValueProfile) profile.mDefaultProfile;
            NameValueProfile valid = (NameValueProfile) validProfile;

            Set<String> set;
            Iterator<String> keys;
            set = defualt.mNameValueMap.keySet();
            keys = set.iterator();

            while (keys.hasNext()) {
                String key = keys.next();
                if (!valid.mNameValueMap.containsKey(key)) {
                    Log.d(TAG, "merge default key----------" + key);
                    valid.mNameValueMap.put(key, defualt.getValue(key));
                }
            }
        }

        if (validProfile != null)

        {
            mergeProfile(commonProfile, validProfile, map);
        }


    }

    /* */
    protected void changeGpriValueFromLGE(HashMap map, ProfileData validProfile) {
    }

    public void loadLgProfile(String path, HashMap<String, String> map, LgeMccMncSimInfo siminfo) {
        try {
            File file = new File(path);
            in = new FileReader(file);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return;
        }
        try {
            factory = XmlPullParserFactory.newInstance();
            parser = factory.newPullParser();
            parser.setInput(in);
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        }

        getMatchedProfile(parser, siminfo, map);

    }

}

