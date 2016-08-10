package com.huaqin.ecidparser.utils;

import android.text.TextUtils;

public class LgeMccMncSimInfo {

	private String mMcc;
	private String mMnc;
	private String mGid;
	private String mSpn;
	private String mImsi;
	private int mPhoneId;

	public void setMcc(String mMcc) {
		this.mMcc = mMcc;
	}

	public void setMnc(String mMnc) {
		this.mMnc = mMnc;
	}

	public void setGid(String mGid) {
		this.mGid = mGid;
	}

	public void setSpn(String mSpn) {
		this.mSpn = mSpn;
	}

	public void setImsi(String mImsi) {
		this.mImsi = mImsi;
	}

	public void setPhoneId(int mPhoneId) {
		this.mPhoneId = mPhoneId;
	}

	public LgeMccMncSimInfo(String mcc, String mnc, String gid, String spn, String imsi, int phoneId) {
        mMcc = mcc;
        mMnc = mnc;

        mGid = gid;
        mSpn = spn;
        mImsi = imsi;
		mPhoneId = phoneId;
    }

	public LgeMccMncSimInfo(String mcc, String mnc) {
		this(mcc,mnc,null,null,null,0);
	}
	public boolean isNull() {
        return TextUtils.isEmpty(mMcc) && TextUtils.isEmpty(mMnc);
    }
	
	public String getMcc() {
		return mMcc;
	}
	
	public String getMnc() {
		return mMnc;
	}

	public String getGid() {
		return mGid;
	}

	public String getSpn() {
		return mSpn;
	}

	public String getImsi() {
		return mImsi;
	}

	public int getPhoneId() {
		return mPhoneId;
	}
}
