package com.huaqin.ecidparser.bookmarks;

import android.util.Log;

import com.huaqin.ecidparser.utils.GeneralParserAttribute;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import java.util.ArrayList;
import java.util.HashMap;
/**
 * Created by shiguibiao on 16-8-5.
 */

public class BrowserProfile  extends ProfileData {
    public static final String TAG = Utils.APP;
    public String homepage;
    // LGE_WEB jinwook.ahn 20130222 add singlebinary variable
    public String singlebinary;
    public String bookmark_read_only;
    public ArrayList<Bookmark> bookmarks = new ArrayList<Bookmark>();
    public HashMap<String, String> boomap = null;

    // LGE_WEB alice.ohe 20140410 Auto profile parser bug fix
    private int matchScore = GeneralParserAttribute.NO_MATCH;

    public BrowserProfile() {
    }

    // LGE_WEB [[ alice.ohe 20140410 Auto profile parser bug fix
    public void setMatchScore(int matchScore) {
        this.matchScore = matchScore;
        Log.i(TAG, "setMachedScore = " + matchScore);

    }

    public int getMatchScore() {
        return matchScore;
    }
    // LGE_WEB ]] alice.ohe 20140410 Auto profile parser bug fix


    public void addBookmark(String name, String url) {
        bookmarks.add(new Bookmark(name, url));
    }

    public void addBookmark(String name, String url, String read_only) {
        bookmarks.add(new Bookmark(name, url, read_only));
    }

    public void setprofiles(String str1, String str2, String str3) {


    }
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("homepage: " + homepage + "\n");

        for (Bookmark b : bookmarks) {
            sb.append("bookmark: " + b.name + " " + b.url + " " + b.read_only + "\n");
        }

        sb.append("bookmark_read_only: " + bookmark_read_only + "\n");
        if (sb == null){
            return null;
        }

        return sb.toString();
    }
}
