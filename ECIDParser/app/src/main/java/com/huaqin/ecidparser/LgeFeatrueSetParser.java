package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;

import static com.huaqin.ecidparser.utils.SIMInfoConstants.ATTR_NAME_COUNTRY;
import static com.huaqin.ecidparser.utils.SIMInfoConstants.ATTR_NAME_OPERATOR;

public class LgeFeatrueSetParser extends GeneralProfileParser  {

	private boolean mUsingfeatureOpen = false;
	public LgeFeatrueSetParser(Context context) {
		super(context);
	
	}

	
	
	public HashMap<String, String> loadLgProfile(String path, HashMap<String, String> map, LgeMccMncSimInfo siminfo) {

		try {
			File file = new File(path);
			if (file.exists()) 
				mUsingfeatureOpen = true;
			
			in = new FileReader(file);

		} catch (FileNotFoundException e) {
			mUsingfeatureOpen = false;
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
		
		return cp.getValueMap();
	}


	@Override
	public ProfileData getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map) {

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
				else if (ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
					if (mUsingfeatureOpen) {
						String operatorValue = parser.getAttributeValue(null, ATTR_NAME_OPERATOR);
						if (operatorValue != null) {
							String countryValue = parser.getAttributeValue(null, ATTR_NAME_COUNTRY);
							ProfileData floatingProfile = getMatchedFeatureByCupssRootDir(parser, operatorValue, countryValue);
							if (floatingProfile != null) {
								if (DBG) { Log.d(TAG, "[featuresetOpen] common : \n" + (NameValueProfile)featureProfile); }
								if (DBG) { Log.d(TAG, "[featuresetOpen] ntcode : \n" + (NameValueProfile)floatingProfile); }
                                //<2015/12/15-junam.hwang, [D5][PORTING][COMMON][FLEX2][][] modify the gpri mapping
								featureProfile = mergeProfileIfNeeded(featureProfile, floatingProfile, null, map);  // featureProfile is overrided by ntcodeProfile.
                                //>2015/12/15-junam.hwang
								if (DBG) { Log.d(TAG, "[featuresetOpen] merged : \n" + (NameValueProfile)featureProfile); }
								mUsingfeatureOpen = false;
								break;
							} else {
								continue;
							}
						}
					}
					// LGE_CHANGE_E, [SMS_Patch_0344] [TEL-FRW-MSG@lge.com][GLOBAL], 2015-02-12, Add routine to support featuresetOpen in Telephony Auto Profiling ]
					featureProfile = readProfile(parser);
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
        //<2015/12/15-junam.hwang, [D5][PORTING][COMMON][FLEX2][][] modify the gpri mapping
		return mergeProfileIfNeeded(commonProfile, validProfile, featureProfile, map);
        //>2015/12/15-junam.hwang
	}



	@Override
	protected ProfileData getMatchedFeatureByCupssRootDir(XmlPullParser parser,
			String operatorValue, String countryValue) {

		 String cupssRootDir = getSystemProperties(SYSTEM_PROP_CUPSS_ROOTDIR);
		 if (cupssRootDir.equals("/data/local/cust")) {
			 cupssRootDir = getSystemProperties(SYSTEM_PROP_CUPSS_SUBCA);
		 }
		 String cupssTarget = String.format("%s_%s", operatorValue, countryValue);
		 ProfileData floatingProfile = null;
		 try {
			 if (ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
				 nextElement(parser);
			 }
			 if (cupssRootDir.toUpperCase().contains(cupssTarget.toUpperCase())) {
				 Log.d(TAG, "matched ntcode parse from xml : " + cupssTarget );
				 if (ELEMENT_NAME_ITEM.equals(parser.getName())) {
					 floatingProfile = readProfile(parser);
				 } else {
					 floatingProfile = new NameValueProfile();
				 }
			 } else {  // Move Next ntcode feature
				 while (ELEMENT_NAME_ITEM.equals(parser.getName())) {
					 nextElement(parser);
				 }
			 }
		 }
		 catch (XmlPullParserException e) {
				e.printStackTrace();
		 } 
		 catch (IOException e) {
			 e.printStackTrace();
		 }
		 
		 return floatingProfile;
	 
	}
}
