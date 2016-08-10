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
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.StringTokenizer;
/**
 * Created by shiguibiao on 16-8-4.
 */

public class GeneralProfileParser  implements GeneralParserAttribute{

    public static final String TAG = Utils.APP;
    public static final boolean DBG = false;
    public static final boolean VDBG = true;
    public Context mContext;
    public FileReader in = null;
    public XmlPullParserFactory factory;
    public XmlPullParser parser = null;
    public ProfileData parseData = null;
    boolean isFileExist = true;

    public final static int FLAGS_NO_MATCH = 0;
    public final static int FLAGS_MATCH_FOR_NO_PRI = 1 << 0; // 1
    public final static int FLAGS_MATCH_IMSI = 1 << 2; // 4
    public final static int FLAGS_MATCH_GID = 1 << 3; // 8
    public final static int FLAGS_MATCH_SPN = 1 << 4;
    public final static int FLAGS_MATCH_MNC = 1 << 5;
    public final static int FLAGS_MATCH_MCC = 1 << 6;

    public static boolean mXmlMatchingData = false;

    public static int mPhoneId = 0;
    public GeneralProfileParser(Context context) {
        mContext = context;

    }



    protected class MatchedProfile {
        public ProfileData mBestMatchedProfile;
        public ProfileData mCandidateProfile;
        public ProfileData mDefaultProfile;
    }

    public static class NameValueProfile extends ProfileData {
        private HashMap<String, String> mNameValueMap = new HashMap<String, String>();

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


    //<2015/12/15-junam.hwang, [D5][PORTING][COMMON][FLEX2][][] modify the gpri mapping
    protected ProfileData mergeProfileIfNeeded(ProfileData globalProfile,
                                               ProfileData matchedProfile, ProfileData featureProfile, HashMap<String, String> map) {
        if (globalProfile == null && featureProfile == null && matchedProfile == null) {
            return null;
        }

        // In case metched profile is null -> check feature set and common profile.
        if (matchedProfile == null) {

            //return feature set profile and common
            if (featureProfile != null) {
                return mergeProfile(globalProfile, featureProfile, null, map);
            }

            // In case matched profile and feature set are null, return common profile

            changeGpriValueFromLGE(map, globalProfile);
            return globalProfile;
        }

        // retun matched profile and feature set.
        return mergeProfile(globalProfile, matchedProfile, featureProfile, map);
    }
//>2015/12/15-junam.hwang




    /**
     * This method will be called when needs to merge commonProfile and matchedProfile
     *
     * @param commonProfile which has default attribute
     * @param matchedProfile matched
     * @param featureProfile which include feature set eunheon.kim
     * @return The ProfileData merged
     */
//<2015/12/15-junam.hwang, [D5][PORTING][COMMON][FLEX2][][] modify the gpri mapping
    protected ProfileData mergeProfile(ProfileData commonProfile, ProfileData matchedProfile,
                                       ProfileData featureProfile, HashMap<String, String> map) {
        NameValueProfile cp = (NameValueProfile)commonProfile;
        NameValueProfile mp = (NameValueProfile)matchedProfile;
        NameValueProfile fp = (NameValueProfile)featureProfile;

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

        if (fp != null) {
            // Set feature Profile
            set = fp.mNameValueMap.keySet();
            keys = set.iterator();

            while (keys.hasNext()) {
                String key = keys.next();
                if (!mp.mNameValueMap.containsKey(key)) {
                    mp.mNameValueMap.put(key, fp.getValue(key));
                }
            }
        }
//<2015/12/15-junam.hwang, [D5][PORTING][COMMON][FLEX2][][] modify the gpri mapping
        changeGpriValueFromLGE(map, mp);
//>2015/12/15-junam.hwang
        return mp;
    }


    public boolean getValidProfile(MatchedProfile profile, XmlPullParser parser, LgeMccMncSimInfo simInfo) {
        ProfileData p = null;
        boolean found = false;

        String mccValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_MCC);
        String mncValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_MNC);
        String operatorValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_OPERATOR);
        String countryValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_COUNTRY);
        String gidValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_GID);
        String spnValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_SPN);
        String imsiValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_IMSI_RANGE);

        String targetOperator = getSystemProperties(GeneralParserAttribute.OPERATOR);
        String targetCountry = getSystemProperties(GeneralParserAttribute.COUNTRY);


        //		if (!targetOperator.equalsIgnoreCase(operatorValue) || !targetCountry.equalsIgnoreCase(countryValue)) {
        //			Log.d(TAG, "operator or country mismatch");
        //			return false;
        //		}

        boolean isDefault = "true".equals(parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_DEFAULT));

        if (isDefault) {
            // keep the default profile
            if (profile.mDefaultProfile == null) {
                p = setParseDataPrio("3", parser);
                profile.mDefaultProfile = p;
            }

            found = true;

            if (simInfo == null || simInfo.isNull()) {
                return found;
            }
        }

        if (DBG) {
            Log.d(TAG, "[getMatchedProfile] TAG : " + parser.getName());
            Log.d(TAG, "[getMatchedProfile] MCC : " + mccValue);
            Log.d(TAG, "[getMatchedProfile] MNC : " + mncValue);
            Log.d(TAG, "[getMatchedProfile] OPERATOR : " + operatorValue);
            Log.d(TAG, "[getMatchedProfile] COUNTRY : " + countryValue);
        }

        if (matchMccMnc(simInfo, mccValue, mncValue)) {
            // keep the first mccmnc matched profile.
            // input value to candidateProfile in case of no gid, spn & imsi
            if (profile.mCandidateProfile == null && TextUtils.isEmpty(gidValue) && TextUtils.isEmpty(spnValue) && TextUtils.isEmpty(imsiValue)) {
                if (p == null) {
                    p = setParseDataPrio("2", parser);
                }
                profile.mCandidateProfile = p;
                found = true;
            }

            if (DBG) {
                Log.d(TAG, "[getMatchedProfile] GID : " + gidValue);
                Log.d(TAG, "[getMatchedProfile] SPN : " + spnValue);
                Log.d(TAG, "[getMatchedProfile] IMSI : " + imsiValue);
            }
            if (profile.mBestMatchedProfile == null && (!TextUtils.isEmpty(gidValue) || !TextUtils.isEmpty(spnValue) || !TextUtils.isEmpty(imsiValue))) {

                if (matchExtension(simInfo, gidValue, spnValue, imsiValue)) {

                    profile.mBestMatchedProfile = setParseDataPrio("1", parser);

                    found = true;

                }
            }
        }

        return found;
    }

    public ProfileData setParseDataPrio(String prio, XmlPullParser parser) {
        ProfileData p = null;
        try {
            p = readProfile(parser);
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        Log.d(TAG, prio + " is found");
        ((NameValueProfile)p).setValue("p", prio);

        return p;
    }

    /**
     * This method will be called whenever the parser meets &lt;Profile&gt;
     *
     * @param parser XmlPullParser
     * @return The ProfileData object
     */
    protected ProfileData readProfile(XmlPullParser parser)
            throws XmlPullParserException, IOException {

        NameValueProfile p = new NameValueProfile();
        int type;

        while (GeneralParserAttribute.ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
                GeneralParserAttribute.ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
            nextElement(parser);
        }

        while (GeneralParserAttribute.ELEMENT_NAME_ITEM.equals(parser.getName())) {

            String tag = parser.getName();
            if (DBG) {
                Log.d(TAG, "[readProfile] TAG : " + tag);
            }

            String key = parser.getAttributeValue(null, GeneralParserAttribute.ATTR_NAME);
            if (key != null) {
                type = parser.next();
                if (type == XmlPullParser.TEXT) {
                    String value = parser.getText();
                    p.setValue(key, value);
                    if (DBG) {
                        Log.d(TAG, "[readProfile] KEY : " + key + ", VALUE : " + value);
                    }
                }
            }
            nextElement(parser);
        }

        return (ProfileData)p;
    }

    protected boolean matchExtension(LgeMccMncSimInfo simInfo, String gidParsed, String spnParsed, String imsiParsed) {
        if (simInfo == null) {
            return false;
        }

        String gid = simInfo.getGid();
        String spn = simInfo.getSpn();
        String imsi = simInfo.getImsi();

        if (TextUtils.isEmpty(gid) && TextUtils.isEmpty(spn) && TextUtils.isEmpty(imsi)) {
            return false;
        }

        // Number of several SIMs are empty in the parameter (gid, spn & imsi).
        // return false, in case of missmatch of parameter in the sim with parameter in the xml
        // return true, in case that although parameter in the sim exist, parameter in the xml in not exist.
        // Although the parameters(spn, gid & imsi) are exist in the sim, SKIP if those are not exist in the xml.
        if (!TextUtils.isEmpty(gid)) {

            int gidLength = gid.length();
            //LGE_CHANGE_S, [Call_Patch_0049][CALL_FRW][COMMON], 2014-08-27, R cable simcard(214 06-12) gid="00" stored because incorrect matching. {
            if (gidParsed != null && ("00".equals(gid) || !existInTokens(gidParsed, gid, gidLength))) {
                //LGE_CHANGE_E, [Call_Patch_0049][CALL_FRW][COMMON], 2014-08-27, R cable simcard(214 06-12) gid="00" stored because incorrect matching. }
                if (DBG) { Log.d(TAG, "[matchExtension] gid is not null"); }

                return false;
            }
        } else {
            // GID(SIM) is empty but GID(XML) is not empty
            if (gidParsed != null) {
                return false;
            }
        }

        if (spn != null) {
            if (spnParsed != null && !existInTokens(spnParsed, spn)) {
                if (DBG) { Log.d(TAG, "[matchExtension] spn is not null"); }

                return false;
            }
        } else {
            // SPN(SIM) is empty but SPN(XML) is not empty
            if (spnParsed != null) {
                return false;
            }
        }

        if (imsiParsed != null && imsiParsed.length() != 0) {
            if (!matchImsi(imsiParsed, imsi)) {
                return false;
            }
        }

        if (DBG) {
            Log.v(TAG, "[matchExtension] true");
        }
        return true;
    }

    /*[LGSI-TELEPHONY][sarmistha.pani][TD342174 Contact apk crash][05.06.2013][START]
     * Contacts Apk crash due to Null exception while accessing Imsi length in profileParser . At this point IMSI is null
     */
    protected boolean matchImsi(String imsiParsed, String imsi) {
        boolean found = false;
        if (imsi != null) {
            int imsiLength = imsi.length();

            StringTokenizer st = new StringTokenizer(imsiParsed, ",");
            while (!found && st.hasMoreTokens()) {
                String t = st.nextToken();
                int len = t.length();

                if (len > imsiLength) {
                    //Log.e(TAG, "invalid imsi or xml has error - xml: " + t + " imsi: " + sim.imsi);
                    continue;
                }

                int i;
                for (i = 0; i < len; i++) {
                    char c = t.charAt(i);
                    //LGE_CHANGE_S, [Call_Patch_0085][CALL_FRW][GLOBAL], 2014-12-22, Imsi parse error fix, when contained the capital letter 'X'. {
                    if ((c != 'x' && c != 'X') && c != imsi.charAt(i)) {
                        //LGE_CHANGE_E, [Call_Patch_0085][CALL_FRW][GLOBAL], 2014-12-22, Imsi parse error fix, when contained the capital letter 'X'. }
                        break;
                    }
                }
                if (i == len) {
                    found = true;
                }
            }
        }
        return found;
    }
	/*[LGSI-TELEPHONY][sarmistha.pani][TD342174 Contact apk crash][05.06.2013][END]*/

    protected boolean existInTokens(String string, String v) {

        if (string == null) {
            return false;
        }

        StringTokenizer st = new StringTokenizer(string, ",");
        while (st.hasMoreTokens()) {
            if (st.nextToken().equals(v)) {
                return true;
            }
        }
        return false;
    }

    protected boolean existInTokens(String string, String v, int len) {
        if (string == null || v == null) {
            return false;
        }

        int xml_length = string.length();
        int final_length;

        if (xml_length > len) {
            final_length = len;
        }
        else {
            final_length = xml_length;
        }

        if (DBG) { Log.d(TAG, "[existInTokens] final length : " + final_length); }

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
                if (existInTokens(mccParsed, mcc) && existInTokens(mncParsed, mnc)) {
                    //if (TextUtils.equals(mcc, mccParsed) && TextUtils.equals(mnc, mncParsed)) {
                    if (DBG) { Log.d(TAG, "[matchMccMnc] true"); }
                    return true;
                }
            }
        }
        if (DBG) { Log.d(TAG, "[matchMccMnc] false"); }

        return false;
    }


    protected final void beginDocument(XmlPullParser parser, String firstElementName)
            throws XmlPullParserException, IOException {
        int type;
        while ((type = parser.next()) != XmlPullParser.START_TAG && type != XmlPullParser.END_DOCUMENT) {
            ;   // do nothing
        }

        if (type != XmlPullParser.START_TAG) {
            throw new XmlPullParserException("No start tag found");
        }

        String first = parser.getName();
        if (!firstElementName.equals(first)) {
            throw new XmlPullParserException("Unexpected start tag: found " + first + ", expected "
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

    protected final void skipCurrentElement(XmlPullParser parser)
            throws XmlPullParserException, IOException {

        nextElement(parser);
        if (DBG) { Log.d(TAG, "[skipCurrentElement] nextElement : " + parser.getName()); }

        if (GeneralParserAttribute.ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
                GeneralParserAttribute.ELEMENT_NAME_PROFILE.equals(parser.getName())) {
            return;
        }

        while ((parser.next()) != XmlPullParser.END_DOCUMENT) {
            if (GeneralParserAttribute.ELEMENT_NAME_ITEM.equals(parser.getName())) {
                nextElement(parser);
            }

            if (DBG) { Log.d(TAG, "[skipCurrentElement] currentElement : " + parser.getName()); }

            if (GeneralParserAttribute.ELEMENT_NAME_PROFILE.equals(parser.getName())) {
                break;
            }
        }
    }

    /**
     * Gets a matched profile from a XmlPullParser
     *
     * @param parser XmlPullParser object
     * @param simInfo The SIM card information
     * @param map add to preference  eunheon.kim
     * @return The ProfileData object matched
     */
    protected ProfileData getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map) {return null;}

    protected ProfileData getMatchedFeatureByCupssRootDir(XmlPullParser parser, String operatorValue, String countryValue) {return null;}

    /* */
    protected void changeGpriValueFromLGE(HashMap map,  ProfileData validProfile) {}


    public String loadLgProfileToString(String path, HashMap<String, String> map, LgeMccMncSimInfo siminfo)
    {
        return null;
    }


    public HashMap<String, String> loadLgProfile(String path, HashMap<String, String> map, LgeMccMncSimInfo siminfo)
    {
        try {
            File file = new File(path);
            in = new FileReader(file);

        } catch (FileNotFoundException e) {
            isFileExist = false;
            e.printStackTrace();
            return null;
        }

        try {
            factory = XmlPullParserFactory.newInstance();
            parser = factory.newPullParser();
            parser.setInput(in);

        } catch (XmlPullParserException e) {
            e.printStackTrace();
        }

        ProfileData parsedData = getMatchedProfile(parser, siminfo, map);
        NameValueProfile cp = (NameValueProfile)parsedData;

        if (cp == null) {
            Log.e(TAG, "parseredData is null");
            return null;
        }

        return cp.mNameValueMap;

    };

    public String loadLgProfile(String path, String profile, LgeMccMncSimInfo siminfo)
    {
        String matchedProfile = null;
        HashMap<String,String> map = new HashMap<String,String>();
        loadLgProfile(path, map, siminfo);

        Iterator<String> key = map.keySet().iterator();

        while(key.hasNext())
        {
            String tag = key.next();
            Log.d(TAG, "loadLgProfile by profile : key : "+tag+" value : "+map.get(tag));
            if (profile.equals(tag)) {
                matchedProfile =  map.get(tag);
            }
        }

        return matchedProfile;
    };

    protected  String getSystemProperties(String properties) {
        String value = "";
        Context context = mContext;
        try {
            Class<?> SystemProperties =
                    context.getClassLoader().loadClass("android.os.SystemProperties");
            Class<?>[] types = new Class[1];
            types[0] = String.class;
            Object[] params = new Object[1];
            params[0] = new String(properties);

            Method get = SystemProperties.getMethod("get", types);
            value = (String) get.invoke(SystemProperties, params);

        } catch (Exception e) {
            Log.e(TAG, "get system properties fail.");
        }
        return value;
    }
}

