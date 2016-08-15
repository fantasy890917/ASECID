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
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

public class LgeCBConfigParser extends GeneralProfileParser implements CBParserAttribute{

    private static final String TAG = Utils.APP+LgeCBConfigParser.class.getSimpleName();

    private static ArrayList<String> mCBChannelList =null;
    private static ArrayList<String> mCBChannelNameList =null;

	public LgeCBConfigParser(Context context) {
		super(context);

	}

    @Override
    protected ProfileData readProfile(XmlPullParser parser)
            throws XmlPullParserException, IOException {
        NameValueProfile p = new NameValueProfile();

        while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
                ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
            nextElement(parser);
        }
        Log.d(TAG,"readProfile---valid Element name="+parser.getName());
        while (parser.getName() != null
                &&(!parser.getName().equals(ELEMENT_NAME_PROFILE))) {

            String tag = parser.getName();
            Log.d(TAG, "[readProfile] TAG : " + tag);

            String key = parser.getName();
            if (key != null) {
                int type = parser.next();
                if (type == XmlPullParser.TEXT) {
                    String value = parser.getText();
                    p.setValue(key, value);
                    Log.d(TAG, "[readProfile] KEY : " + key + ", VALUE : " + value);
                }
            }
            nextElement(parser);
        }

        return (ProfileData)p;
    }

    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data) {
        Log.d(TAG,"changeGpriValueFromLGE");
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put("Message@Cell_Broadcast_Receive", ATTR_CB_DEFAULT_SWITCH);
        matchmap.put("Message@Cell_Broadcast_Channel_Number_#", ATTR_CB_DEFAULT_CH_LIST);
        matchmap.put("Message@Cell_Broadcast_Support_EU_Alert", ATTR_CB_DEFAULT_EU_ALERT);
        matchmap.put("Message@Cell_Broadcast_Channel_Name_#", ATTR_CB_DEFAULT_CH_NAME);

        Iterator<String> key = matchmap.keySet().iterator(); 
        
        while(key.hasNext()) {
            String tag = key.next();
            String matchString_Value = (String) matchmap.get(tag);
            String value = ((NameValueProfile)data).getValue(matchString_Value);
            Log.d(TAG, "[CBResult]: tag = "+matchString_Value +" ,value =" +value);
            if (value != null) {
                if (ATTR_CB_DEFAULT_CH_LIST.equals(matchString_Value)) {
                    String[] cblist = value.split(",");
                    mCBChannelList = new ArrayList<String>();
                    for (int i = 0; i < cblist.length; i++)
                    {
                        mCBChannelList.add(cblist[i]);
                    }
                } else if (ATTR_CB_DEFAULT_CH_NAME.equals(matchString_Value)) {
                    String[] cblistname = value.split(",");
                    mCBChannelNameList = new ArrayList<String>();
                    for (int i = 0; i < cblistname.length; i++)
                    {
                        mCBChannelNameList.add(cblistname[i]);
                    }
                } else {
                    hashmap.put(tag, value);
                }
            }
        }
    }

    public ArrayList<String> getChannelList(){
        return mCBChannelList;
    }

    public ArrayList<String> getChannelNameList(){
        return mCBChannelNameList;
    }

}

