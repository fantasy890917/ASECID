package com.huaqin.ecidparser;

import android.content.Context;
import android.provider.Settings;
import android.util.Log;

import com.huaqin.ecidparser.telephony.LteInfoConstants;
import com.huaqin.ecidparser.utils.CAItem;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Iterator;
public class LgeLTEConfigParser extends GeneralProfileParser implements LteInfoConstants {
    private static final String TAG = Utils.APP+LgeLTEConfigParser.class.getName();
    //<siminfo default="true" /> <siminfo operator="default" country="" mcc="" mnc="" />
    public HashMap<String, String> mDefaultMatchMap = new HashMap<String,String>();
    //mccmnc
    public HashMap<String, String> mCommonMatchMap = new HashMap<String,String>();
    //mccmnc+gid+spn+imsi
    public HashMap<String, String> mBestMatchMap = new HashMap<String,String>();

	public LgeLTEConfigParser(Context context) {
		super(context);
	}

	public HashMap<String, String> loadLgProfile(String path, LgeMccMncSimInfo siminfo) {
        Log.d(TAG, "loadLgProfile");
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
    }

    void changeGpriValueFromLGE(HashMap<String, String> hashmap, HashMap<String, String> data)
    {
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put(PROPERTY_LTEREADY_VALUE, ATTR_NAME_VALUE);
        matchmap.put(PROPERTY_LTEREADY_MODE,ATTR_NAME_LTE_MODE);

        Iterator<String> key = matchmap.keySet().iterator();

        while(key.hasNext())
        {
            String tag = key.next();
            String matchString_Value = (String) matchmap.get(tag);
            String value =data.get(matchString_Value);
            if (value != null)
            {
                if(PROPERTY_LTEREADY_MODE.equals(tag)){
                    Settings.System.putInt(mContext.getContentResolver(), LTEREADY_MODE_DB_NAME,
                            value.equals("LTE") ? 1 : 0);
                }
                //Log.d(TAG,"read from db==="+Settings.System.getInt(mContext.getContentResolver(), LTEREADY_MODE_DB_NAME,-1));
                Log.d(TAG,"put key:="+tag+" value:="+value);
                hashmap.put(tag, value);
            }
        }
    }


	protected CAItem getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo) {

        Log.d(TAG, "LgeLTEConfigParser getMatchedProfile");
		int  match_priority  = -1;
		boolean match_siminfo = false;
        CAItem caItem = new CAItem();
        mXmlMatchingData = false;
		try {
			if (parser != null) {
				parser.next();
				int eventType = parser.getEventType();
				while (eventType != XmlPullParser.END_DOCUMENT) {
					if (eventType == XmlPullParser.START_TAG) {
						String startTag = parser.getName();
                        if ( ELEMENT_NAME_LTE.equals(startTag) ) {
                            Log.d(TAG, "new++++++++++++++++++++++++++++++profile");
                        } else if ( ELEMENT_NAME_SIMINFO.equals(startTag)) {

                            if(mXmlMatchingData){
                                Log.d(TAG, "has parser correct data ,exit");
                                break;
                            }
                            match_priority = Utils.getMatchPriority(parser,simInfo,caItem);
							if(match_priority> -1){
								match_siminfo =  true;
							}else{
                                match_siminfo = false;
                            }

                            if(match_siminfo){
                                int AttributeNum = parser.getAttributeCount();
                                String tempValue=null;
                                String tempLteMode=null;
                                if(AttributeNum>1){
                                    if ( parser.getAttributeName(AttributeNum-1).equalsIgnoreCase(LteInfoConstants.ATTR_NAME_LTE_MODE) ) {
                                        tempLteMode = parser.getAttributeValue(AttributeNum-1);
                                        caItem.addSettingItem(LteInfoConstants.ATTR_NAME_LTE_MODE,tempLteMode);
                                        Log.d(TAG, "tempLteMode =="+tempLteMode);
                                    }

                                    if ( parser.getAttributeName(AttributeNum-2).equalsIgnoreCase(LteInfoConstants.ATTR_NAME_VALUE) ) {
                                        tempValue = parser.getAttributeValue(AttributeNum-2);
                                        caItem.addSettingItem(LteInfoConstants.ATTR_NAME_VALUE,tempValue);
                                        Log.d(TAG, "tempValue =="+tempValue);
                                    }


                                }
                                mXmlMatchingData = true;
                            }

						}
					} else if ( eventType == XmlPullParser.END_TAG ) {
						if ( ELEMENT_NAME_LTE.equals(parser.getName()) ) {
							match_siminfo = false;
						}
					}

					eventType = parser.next();

				}
			}
		} catch ( Exception e ) {
			// There is some problem in XML parsing process
			e.printStackTrace();
		}
		return caItem;	
	}

}


