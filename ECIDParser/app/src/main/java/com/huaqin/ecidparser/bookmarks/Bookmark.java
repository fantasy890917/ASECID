package com.huaqin.ecidparser.bookmarks;

/**
 * Created by shiguibiao on 16-8-5.
 */

public class Bookmark {
    public String mName;
    public String mUrl;
    public int mRead_only;

    public int getRead_only() {
        return mRead_only;
    }

    public void setRead_only(int read_only) {
        mRead_only = read_only;
    }

    public void setUrl(String url) {
        mUrl = url;
    }

    public void setName(String name) {
        mName = name;
    }

    public String getUrl() {
        return mUrl;
    }

    public String getName() {
        return mName;
    }

    public Bookmark() {
        this(null,null);
    }

    public Bookmark(String name, String url) {
        mName = name;
        mUrl = url;
        mRead_only = -1;
    }

    public Bookmark(String name, String url, int read_only) {
        mName = name;
        mUrl = url;
        mRead_only = read_only;
    }
}