package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.cellbroadcast.CBParserAttribute;
import com.huaqin.ecidparser.utils.CAItem;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Iterator;

public class LgeCBConfigParser extends GeneralProfileParser{

	private static boolean mXmlMatchingData = false;

	public LgeCBConfigParser(Context context) {
		super(context);

	}

	public HashMap<String, String> loadLgProfile(String path, HashMap<String, String> map, LgeMccMncSimInfo siminfo) {
        Log.d(TAG, "LgeCBConfigParser loadLgProfile");
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

        CAItem cp = (CAItem)parsedData;

        if (cp.getValueMap() != null)
        {
            changeGpriValueFromLGE(map, cp.getValueMap());
        }

        return cp.getValueMap();
    }

    void changeGpriValueFromLGE(HashMap<String, String> hashmap, HashMap<String, String> data)
    {
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put("Message@Cell_Broadcast_Receive", CBParserAttribute.CB_DEFAULT_SWITCH_KEY);
        matchmap.put("Message@Cell_Broadcast_Channel_Number_#", CBParserAttribute.CB_DEFAULT_CH_LIST_KEY);
        matchmap.put("Message@Cell_Broadcast_Support_EU_Alert", CBParserAttribute.CB_DEFAULT_EU_ALERT_KEY);
        matchmap.put("Message@Cell_Broadcast_Channel_Name_#", CBParserAttribute.CB_DEFAULT_CH_NAME_KEY);

        Iterator<String> key = matchmap.keySet().iterator(); 
        
        while(key.hasNext()) {
            String tag = key.next();
            String matchString_Value = (String) matchmap.get(tag);
            String value = data.get(matchString_Value);
            if (value != null) {
                if ("cb_ch_list".equals(matchString_Value)) {
                    String[] cblist = value.split(",");
                    
                    for (int i = 0; i < cblist.length; i++)
                    {
                        String tag_temp = tag + (i+1) ;
                        hashmap.put(tag_temp, cblist[i]);
                        Log.d(TAG, "[CBResult]: tag_temp = "+tag_temp +" ,value =" +cblist[i]);
                    }
                } else if ("cb_ch_list_name".equals(matchString_Value)) {
                    String[] cblistname = value.split(",");
                    
                    for (int i = 0; i < cblistname.length; i++)
                    {
                        String tag_temp = tag + (i+1) ;
                        hashmap.put(tag_temp, cblistname[i]);
                        Log.d(TAG, "[James0310]: tag_temp = "+tag_temp +" ,value =" +cblistname[i]);
                    }
                } else {
                    hashmap.put(tag, value);
                }
            }
        }
    }

	@Override
	protected ProfileData getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map) {
		CAItem item = getMatchedProfile(parser, simInfo, map, null);


		return item;
	}


	protected CAItem getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map, CAItem item) {

        Log.d(TAG, "LgeCBConfigParser getMatchedProfile");
		int  match_priority  = -1;
		boolean match_siminfo = false;
		CAItem caItem = null;

		caItem = new CAItem();

		try {
			if (parser != null) {
				parser.next();
				int eventType = parser.getEventType();    	

				while (eventType != XmlPullParser.END_DOCUMENT) {    
					if (eventType == XmlPullParser.START_TAG) {
						String startTag = parser.getName();
						if ( ELEMENT_NAME_PROFILES.equals(startTag)) {
							// Preceed configuration start TAG
						} else if ( ELEMENT_NAME_PROFILE.equals(startTag) ) {
						        Log.d(TAG, "new++++++++++++++++++++++++++++++profile");				
						} else if ( ELEMENT_NAME_SIMINFO.equals(startTag)) {
							match_priority = Utils.getMatchPriority(parser,simInfo,caItem);
							if(match_priority> -1){
								match_siminfo =  true;
							}
						} else {
							parser.next();
							if ( startTag != null && parser.getText() != null  && match_siminfo) {
								caItem.addSettingItem(startTag, parser.getText());	
								mXmlMatchingData = true;
							}	 
						}
					} else if ( eventType == XmlPullParser.END_TAG ) {
						if ( ELEMENT_NAME_PROFILE.equals(parser.getName()) ) {
							match_siminfo = false;
						}
					}

					eventType = parser.next();
				}
			}
			//           //[WBT_S : 300321] 2012.01.13, seturn810.min@lge.com 
			//           if (parser != null) {
			//               parser.close();
			//           }
			//[WBT_E : 300321] 2012.01.13, seturn810.min@lge.com 
		} catch ( Exception e ) {
			// There is some problem in XML parsing process
			e.printStackTrace();
		}
		return caItem;	
	}

}

