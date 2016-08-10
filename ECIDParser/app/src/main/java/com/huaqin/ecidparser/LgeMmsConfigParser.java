package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

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

public class LgeMmsConfigParser extends GeneralProfileParser {

    public LgeMmsConfigParser(Context context) {
        super(context);
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
            matchmap.put("Message@SMS_Delivery_Report", "sms_dr");
            matchmap.put("Message@SMS_Number", "smsc");
            matchmap.put("Message@SMS_Editable", "smsc_readonly");
            matchmap.put("Message@SMS_Unicode_characters", "sms_char");
            //matchmap.put("Message@Cell_Broadcast_Receive", "sms_sent_time_mode");
            matchmap.put("Message@SMS_Validity_Period", "sms_validity");
            matchmap.put("Message@SMS_Turn_to_MMS_when_SMS_size_is_more_than", "sms_concat");
            matchmap.put("Message@MMS_Report_Request", "mms_dr_r");
            matchmap.put("Message@SMS_Remove_SMS_templates", "sms_templates_removable");

            matchmap.put("Message@MMS_Allow_Report", "mms_dr_a");
            matchmap.put("Message@MMS_Request_reply", "mms_rr_r");
            matchmap.put("Message@MMS_Allow_reply", "mms_rr_a");
            matchmap.put("Message@MMS_Home", "auto_retr");
            matchmap.put("Message@MMS_Roaming", "auto_retr_r");
            matchmap.put("Message@MMS_MMS_Priority", "mms_priority");
            matchmap.put("Message@MMS_Validity_period", "mms_validity");
            matchmap.put("Message@MMS_Maximum_Size", "mms_size");

            matchmap.put("Message@MMS_Creation_mode", "mms_creation");
            matchmap.put("Message@MMS_Slide_Duration_(in_seconds)", "slide_dur");
            matchmap.put("Message@MMS_Advertisement", "recv_adv");
            matchmap.put("Message@Cell_Broadcast_Receive", "cb_on");
            matchmap.put("Internet@Receive_push_message", "push_on");
            //matchmap.put("Message@MMS_Maximum_Size", "del_old");

            Iterator<String> key = matchmap.keySet().iterator(); 
            
            while(key.hasNext()) 
            {
                String tag = key.next();
                String matchString_Value = (String) matchmap.get(tag);
                String value =data.get(matchString_Value);
                if (value != null) 
                {
				  if ("smsc_readonly".equals(matchString_Value))
                  {
                    value = "1".equals(value)?"0":"1" ; 
                  }
                    hashmap.put(tag, value);
                }
            }
        }

	@Override
	protected ProfileData getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map) {
		CAItem item = getMatchedProfile(parser, simInfo, map, null);


		return item;
	}


	protected CAItem getMatchedProfile(XmlPullParser parser, LgeMccMncSimInfo simInfo, HashMap map, CAItem item) {


		int  match_priority  = -1;
		boolean match_siminfo = false;
        boolean match_default= false;
		CAItem caItem = new CAItem();
        CAItem defaultCaItem = new CAItem();
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
                            if(mXmlMatchingData){
                                Log.d(TAG, "has parser correct data ,exit");
                                break;
                            }
                            Log.d(TAG, "new++++++++++++++++++++++++++++++profile");
                            match_default = false;
							match_siminfo = false;
						} else if ( ELEMENT_NAME_SIMINFO.equals(startTag)) {
							match_priority = Utils.getMatchPriority(parser,simInfo,caItem);

                            if(match_priority == Utils.MATCH_PRIORITY_OPERATOR_DEFAULT){
                                match_default = true;
                            }else if(match_priority> 0){
                                caItem.clearSettingItem();
                                match_siminfo =  true;
                                match_default = false;
                            }

						} else {
							// Check MNC/MCC/SPN values with device's and if current parsed informations are same
							// with device, store settings items to shared user preferences. Until meeting END tag of CAItem
							parser.next();
                            if(startTag != null && parser.getText() != null  && match_default) {
                                defaultCaItem.addSettingItem(startTag, parser.getText());
                                Log.d(TAG,"match_default========");
                                caItem = defaultCaItem;
                            }

							if ( startTag != null && parser.getText() != null  && match_siminfo) {
                                Log.d(TAG,"match_siminfo========");
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

		} catch ( Exception e ) {
			// There is some problem in XML parsing process
			e.printStackTrace();
		}
            
		return caItem;	
	}
}


