package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.bookmarks.Bookmark;
import com.huaqin.ecidparser.bookmarks.BrowserProfile;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.SIMInfoConstants;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.StringTokenizer;

public class LgeBrowserProfileParser extends GeneralProfileParser {
	
	
    public LgeBrowserProfileParser(Context context) {
		super(context);
		mContext = context;
	}


    // WBC-6088 : Remove unused method: nextElement(), skipCurrentElement(), skipCurrentProfile()

    // merge two profiles if needed
    protected BrowserProfile mergeProfileIfNeeded(BrowserProfile globalProfile,
                                                  BrowserProfile matchedProfile, HashMap<String, String> map) {

        if (globalProfile == null) {
            changeGpriValueFromLGE(map, (BrowserProfile)matchedProfile);
            return matchedProfile;
        }

        if (matchedProfile == null) {
            return null;
        }

        return mergeProfile(globalProfile, matchedProfile, map);
    }

    protected boolean existInTokens(String string, String v) {
        StringTokenizer st = new StringTokenizer(string, ",");
        while (st.hasMoreTokens()) {
            if (st.nextToken().equals(v)) {
                return true;
            }
        }
        return false;
    }

    protected int existInTokens(String string, String v, int len, boolean isbrowsertoken) {

        if (string == null) {
            return 0; // gid not found
        }
        if (string != null && (v == null || len == 0)) {
            return 0; // gid not found
        }

        int xml_length = string.length();
        int final_length;
        int tempLength = 0;

        if (xml_length > len) {
            // LGE_WEB jinwook.ahn 20130207 add gid mismatch case / 20130222 add gid exception case
            if (xml_length >= 8 && (tempLength = string.indexOf("F")) != -1) {
                final_length = tempLength;
            } else {
                return -1; //gid mismatched
            }
        } else {
            final_length = xml_length;
        }

        // WBC-2805 jinwook.ahn 20130615 fixed StringIndexOutOfBoundsException
        if (final_length > len) {
            return -1; //gid mismatched
        }

        String fixed_xml_gid = string.substring(0, final_length);
        String fixed_sim_gid = v.substring(0, final_length);

        if (fixed_xml_gid.equalsIgnoreCase(fixed_sim_gid)) {
            return 1; //gid matched
        } else {
            return -1; //gid mismatched
        }
    }

    protected boolean matchMccMnc(LgeMccMncSimInfo sim, String mcc, String mnc) {
        // WBC-6088 : Auto matching-up PRI with GPRI System
        if (sim == null) {
            return false;
        }
        if (mcc == null || !existInTokens(mcc, sim.getMcc())) {
            return false;
        }
        if (mnc == null || !existInTokens(mnc, sim.getMnc())) {
            return false;
        }

        return true;
    }

    
     public String loadLgProfileToString(String path, HashMap<String, String> map, LgeMccMncSimInfo siminfo) {
    	ProfileData parsedData = getMatchedProfile(path, map, siminfo);
    	BrowserProfile cp = (BrowserProfile)parsedData;
		
        if (cp == null){
            Log.e(TAG, " browserprofile is not matched");
            return null;
        }

		return cp.toString();
	}

	// WBC-6088 : Auto matching-up PRI with GPRI System
    public ProfileData getMatchedProfile(String path,  HashMap<String, String> map, LgeMccMncSimInfo sim) {
        ProfileData matchedProfile = null;
        XmlPullParserFactory factory;
        XmlPullParser parser;
        FileReader in = null;
        long startTime = System.nanoTime();

        try {

        	File file = new File(path);
        	in = new FileReader(file);

        	factory = XmlPullParserFactory.newInstance();
        	factory.setNamespaceAware(true);
        	factory.setValidating(false);
        	parser = factory.newPullParser();
        	parser.setInput(in);
        	matchedProfile = parseProfile(parser, sim, map);
        	//            }

        } catch (XmlPullParserException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        Log.i(TAG, "Duration of Profile parsing = " + (System.nanoTime() - startTime) / 1000000);

        return matchedProfile;
    }

    // WBC-6088 : Auto matching-up PRI with GPRI System
    /**
     * Gets a matched profile from a XmlPullParser
     *
     * @param parser XmlPullParser object
     * @param sim The SIM card information
     * @return The ProfileData object matched
     * XmlPullParser type value
     *    START_DOCUMENT(0) END_DOCUMENT(1)
     *    START_TAG(2) END_TAG(3) TEXT(4)
     */
    public BrowserProfile parseProfile(XmlPullParser parser, LgeMccMncSimInfo sim, HashMap<String, String> map) {
        ProfileData commonProfile = null;
        ProfileData bestMatchedProfile = null;
        ProfileData candidateProfile = null;
        ProfileData defaultProfile = null;
        ProfileData validProfile = null;

        boolean endDocument = false;

        int parsingScore = NO_MATCH;
        int candidateScore = NO_MATCH;

        if (parser == null) {
            return null;
        }
        try {
            beginDocument(parser, ELEMENT_NAME_PROFILES);

            while (!endDocument) {
                String tag = parser.getName();
                int type = parser.getEventType();

                // End of docuemnt, exit loop
                if (type == XmlPullParser.END_DOCUMENT) {
                    endDocument = true;
                    break;
                }

                // skip until find START_TAG
                if (type != XmlPullParser.START_TAG) {
                    parser.next();
                    continue;
                }

                // meet STAR_TAG and then  analyze tag
                switch (tag) {
                    case ELEMENT_NAME_SIMINFO:
                        int currentScore = parseLgeMccMncSimInfo(parser, sim);
                        // WBC-6374 : Default profile bug fix
                        if (currentScore == FIND_DEFAULT || currentScore > parsingScore) {
                            Log.i(TAG, "parsing Score [currentScore] =" + currentScore
                                    + "[parsingScore] = " + parsingScore + "[candidateSocre] = "
                                    + candidateScore);
                            parsingScore = currentScore;
                        }
                        break;
                    case ELEMENT_NAME_HOMEPAGE:
                    case ELEMENT_NAME_BOOKMARK:
                        switch (parsingScore) {
                            case FIND_BESTMATCH:
                                bestMatchedProfile = readProfile(parser);
                                if (bestMatchedProfile != null) {
                                    ((BrowserProfile) bestMatchedProfile).setMatchScore(FIND_BESTMATCH);
                                }
                                endDocument = true;
                                Log.i(LOG_TAG, "[FIND] Best matched profile, Stop to find");
                                break;
                            case FIND_DEFAULT:
                                defaultProfile = readProfile(parser);
                                if (defaultProfile != null) {
                                    ((BrowserProfile) defaultProfile).setMatchScore(FIND_BESTMATCH);
                                }
                                parsingScore = NO_MATCH;
                                Log.i(LOG_TAG, "[FIND] Default profile");
                                break;
                            default:
                                if (parsingScore > candidateScore) {
                                    candidateProfile = readProfile(parser);
                                    if (candidateProfile != null) {
                                        ((BrowserProfile) candidateProfile).setMatchScore(parsingScore);
                                    }
                                    candidateScore = parsingScore;
                                    Log.i(LOG_TAG, "[UPDATE] candidate profile is updated and score is [" + candidateScore + "]");

                                }
                                break;
                        }
                        break;
                    case ELEMENT_NAME_COMMONPROFILE:
                        commonProfile = readProfile(parser);
                        Log.i(LOG_TAG, "[FIND] Common profile");
                        break;
                    default:
                        // do nothing
                        break;
                }

                parser.next();

                if (commonProfile != null && defaultProfile != null && bestMatchedProfile != null) {
                    // if you find enough information, exit loop
                    break;
                }
            }
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        validProfile = bestMatchedProfile != null ? bestMatchedProfile : candidateProfile != null ? candidateProfile : defaultProfile;

        return mergeProfileIfNeeded((BrowserProfile)commonProfile, (BrowserProfile)validProfile, map);
    }

    protected void changeGpriValueFromLGE(HashMap hashmap, BrowserProfile data)
    {
        String nametag = "";
        String urltag = "";
        String readonlytag = "";

        hashmap.put("Internet@Home_URL", data.homepage);
        
        for(int i = 1; i<=data.bookmarks.size(); i++)
        {
            Bookmark bmi = data.bookmarks.get(i-1);
            nametag = "Internet@Bookmark_" + i + "_Name" ;
            hashmap.put(nametag, bmi.name);

            urltag = "Internet@Bookmark_" + i + "_Address" ;
            hashmap.put(urltag, bmi.url);

            readonlytag = "Internet@Bookmark_" + i + "_Readonly" ;
            hashmap.put(readonlytag, bmi.read_only);
        }
    }

    // LGE_WEB [[ alice.ohe 20140410 Auto profile parser bug fix
    private int parseLgeMccMncSimInfo(XmlPullParser parser, LgeMccMncSimInfo sim) {
        String mccValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_MCC);
        String mncValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_MNC);
        boolean isDefault = "true".equals(parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_DEFAULT));
        int parsingResult = NO_MATCH;

        if (isDefault) {
            parsingResult = FIND_DEFAULT;
        }

        if (matchMccMnc(sim, mccValue, mncValue)) {
            String gidValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_GID);
            String spnValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_SPN);
            String imsiValue = parser.getAttributeValue(null, SIMInfoConstants.ATTR_NAME_IMSI_RANGE);

            if (sim != null) {
                int compareGID = compareExtensionValue(gidValue, sim.getGid());
                int compareSPN = compareExtensionValue(spnValue, sim.getSpn());
                int compareIMSI = compareExtendsionIMSI(imsiValue, sim);
                if (compareIMSI == NO_MATCH
                        || compareGID == NO_MATCH) {
                    parsingResult = NO_MATCH;
                } else {
                    parsingResult = compareGID + compareSPN + compareIMSI;
                    // WBC-6088 : Auto matching-up PRI with GPRI System
                     if (!"user".equalsIgnoreCase(getSystemProperties("ro.build.type"))) {
                        Log.e(LOG_TAG, "Matching PRI : [mccValue]" + mccValue + " [mncValue] :"
                                + mncValue + " [gidValue] :" + gidValue + " [spnValue] : "
                                + spnValue + " [imsiValue]: " + imsiValue);
                    }
                    Log.e(LOG_TAG, "SCORE: [compareGID]=" + compareGID + "  [compareSPN] ="
                            + compareSPN + "  [compareIMSI] = " + compareIMSI);
                }
            }
        }
        return parsingResult;
    }

    private int compareExtensionValue(String parsedData, String simData) {
        // WBC-6088 : Auto matching-up PRI with GPRI System
        int matchScore = NO_MATCH;

        // WBC-6301 : Fix to NullPointerException
        if (simData == null) {
            if (parsedData == null) {
                matchScore = MATCHCNT;
            }
        } else {
            if (parsedData == null) {
                matchScore = CANDIDATECNT;
            } else {
                int state = existInTokens(parsedData, simData, simData.length(), true);
                if (state == 1)
                {
                    matchScore = MATCHCNT;
                }
            }
        }

        return matchScore;
    }

    private int compareExtendsionIMSI(String parsedIMSI, LgeMccMncSimInfo sim) {
        // WBC-6088 : Auto matching-up PRI with GPRI System
        int matchScore = NO_MATCH;
        // WBC-6301 : Fix to NullPointerException
        if (sim.getImsi() == null) {
            if (parsedIMSI == null) {
                matchScore = MATCHCNT;
            }
        } else {
            if (parsedIMSI == null) {
                matchScore = CANDIDATECNT;
            } else {
                int imsiLength = sim.getImsi().length();
                boolean found = false;
                StringTokenizer st = new StringTokenizer(parsedIMSI, ",");

                while (!found && st.hasMoreTokens()) {
                    String t = st.nextToken();
                    int len = t.length();

                    if (len > imsiLength) {
                        continue;
                    }

                    int i;
                    for (i = 0; i < len; i++) {
                        char c = t.charAt(i);
                        // upper character, X
                        if ((c != 'x' && c != 'X') && c != sim.getImsi().charAt(i)) {
                            break;
                        }
                    }
                    if (i == len) {
                        found = true;
                        matchScore = MATCHCNT;
                    }
                }
            }
        }
        return matchScore;
    }

    
    
    /**
     * This method will be called whenever the parser meets &lt;Profile&gt;
     *
     * @param parser XmlPullParser
     * @return The ProfileData object
     */
    protected BrowserProfile readProfile(XmlPullParser parser) throws XmlPullParserException, IOException {

        BrowserProfile b = new BrowserProfile();

        int startDepth = parser.getDepth();
        int type = parser.getEventType();
        String tag = parser.getName();

        Log.i(LOG_TAG, "readProfile() START [depth] " + startDepth + "[type]=" + type);
        // parse inner element of the <Profile>
        // until loop when parser meet END_DOCMENT or END_TAG of <Profile>
        while (type != XmlPullParser.END_DOCUMENT &&
                !(type == XmlPullParser.END_TAG && parser.getDepth() < startDepth)) {

            // skip until find START_TAG
            if (type != XmlPullParser.START_TAG) {
                type = parser.next();
                continue;
            }
            tag = parser.getName();

            switch (tag) {
                case ELEMENT_NAME_READONLY:
                    String readOnly = parser.getAttributeValue(null, ATTR_VALUE);
                    b.bookmark_read_only = readOnly;
                    Log.i(LOG_TAG, "[READ_ONLY]=" + readOnly);
                    break;
                case ELEMENT_NAME_BOOKMARK:
                    String editable = parser.getAttributeValue(null, "readOnly");
                    String title = parser.getAttributeValue(null, ATTR_NAME);
                    String url = parser.getAttributeValue(null, ATTR_URL);
                    if (editable != null) {
                        b.addBookmark(title, url, editable);
                    } else {
                        b.addBookmark(title, url);
                    }
                    Log.i(LOG_TAG, "[BOOKMARK TITLE]=" + title + " [URL]=" + url);
                    break;
                case ELEMENT_NAME_HOMEPAGE:
                    String homepage = parser.getAttributeValue(null, ATTR_VALUE);
                    b.homepage = homepage;
                    Log.i(LOG_TAG, "[HOMEPAGE]=" + homepage);
                    break;
                case ELEMENT_NAME_SINGLEBINARY:
                    String singleBinary = parser.getAttributeValue(null, ATTR_VALUE);
                    b.singlebinary = singleBinary;
                    Log.i(LOG_TAG, "[SINGLE_BINARY]=" + singleBinary);
                    break;
                default:
                    // do nothing
                    break;

            }
            type = parser.next();
        }
        Log.i(LOG_TAG, "readProfile() END [depth] " + parser.getDepth() + "[type]=" + type);

        return (BrowserProfile)b;
    }

    /**
     * This method will be called when needs to merge commonProfile and matchedProfile
     *
     * @param commonProfile which has default attribute
     * @param matchedProfile matched
     * @return The ProfileData merged
     */
    protected BrowserProfile mergeProfile(BrowserProfile commonProfile,
            BrowserProfile matchedProfile, HashMap<String, String> map) {
        BrowserProfile cp = (BrowserProfile)commonProfile;
        BrowserProfile mp = (BrowserProfile)matchedProfile;

        if (mp.homepage == null) {
            mp.homepage = cp.homepage;
        }

        if (mp.bookmark_read_only == null) {
            mp.bookmark_read_only = cp.bookmark_read_only;
        }

        // LGE_WEB jinwook.ahn 20130222 add singlebinary pasing routine
        if (mp.singlebinary == null) {
            mp.singlebinary = cp.singlebinary;
        }
        // do not merge bookmarks...

        changeGpriValueFromLGE(map, (BrowserProfile)mp);
        
        return mp;
    }
}

