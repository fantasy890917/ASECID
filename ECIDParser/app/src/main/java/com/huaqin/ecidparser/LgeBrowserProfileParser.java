package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.bookmarks.Bookmark;
import com.huaqin.ecidparser.bookmarks.BrowserParserAttribute;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

public class LgeBrowserProfileParser extends GeneralProfileParser
        implements BrowserParserAttribute {

    public ArrayList<Bookmark> mBookmarkList = new ArrayList<Bookmark>();
    private static final String TAG = Utils.APP+LgeBrowserProfileParser.class.getSimpleName();

    public LgeBrowserProfileParser(Context context) {
		super(context);
		mContext = context;
	}

    protected void changeGpriValueFromLGE(HashMap hashmap, ProfileData data)
    {
        Log.d(TAG,"changeGpriValueFromLGE");
        HashMap<String, String> matchmap = new HashMap<String,String>();
        matchmap.put("Browser@bookmark_read_only", "bookmark_read_only");
        matchmap.put("Browser@homepage", "homepage");
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

    
    /**
     * This method will be called whenever the parser meets &lt;Profile&gt;
     *
     * @param parser XmlPullParser
     * @return The ProfileData object
     */
    protected ProfileData readProfile(XmlPullParser parser) throws XmlPullParserException, IOException {

        NameValueProfile p = new NameValueProfile();
        Log.d(TAG,"[readProfile]name="+parser.getName()+" text="+parser.getText());
        while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
                ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
            nextElement(parser);
        }
        while (parser.getName() != null
                &&(!parser.getName().equals(ELEMENT_NAME_PROFILE))) {

            String tag = parser.getName();
            Log.d(TAG, "[readProfile]tag=" + tag);
                switch (tag) {
                    case ELEMENT_NAME_READONLY: {
                        String value = parser.getAttributeValue(null, ATTR_VALUE);
                        p.setValue(tag, value);
                        Log.d(TAG, "[readProfile][READ_ONLY]=" + value);
                        break;
                    }
                    case ELEMENT_NAME_BOOKMARK: {
                        String editable = parser.getAttributeValue(null, ATTR_READONLY);
                        String title = parser.getAttributeValue(null, ATTR_NAME);
                        String url = parser.getAttributeValue(null, ATTR_URL);
                        if (editable != null) {
                            mBookmarkList.add(new Bookmark(title,url, Integer.parseInt(editable)));
                        } else {
                            mBookmarkList.add(new Bookmark(title,url, -1));
                        }
                        Log.d(TAG, "[readProfile][BOOKMARK TITLE]=" + title + " [URL]=" + url);
                        break;
                    }
                    case ELEMENT_NAME_HOMEPAGE: {
                        String value = parser.getAttributeValue(null, ATTR_VALUE);
                        p.setValue(tag, value);
                        Log.d(TAG, "[readProfile][HOMEPAGE]=" + value);
                        break;
                    }
                    default:
                        // do nothing
                        break;

                }
                nextElement(parser);
        }

        return (ProfileData)p;
    }
    public ArrayList<Bookmark> getBoomarkList(){
        return mBookmarkList;
    }
}

