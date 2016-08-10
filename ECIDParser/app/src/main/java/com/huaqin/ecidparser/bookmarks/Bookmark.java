package com.huaqin.ecidparser.bookmarks;

/**
 * Created by shiguibiao on 16-8-5.
 */

public class Bookmark {
    public String name;
    public String url;
    public String read_only;

    public Bookmark(String name, String url) {
        this.name = name;
        this.url = url;
    }

    public Bookmark(String name, String url, String read_only) {
        this.name = name;
        this.url = url;
        this.read_only = read_only;
    }
}