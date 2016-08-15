/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.huaqin.ecidparser;

import android.annotation.SdkConstant;
import android.annotation.SystemApi;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.WorkSource;
import android.text.TextUtils;

import libcore.util.ZoneInfoDB;

import android.util.Log;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ECIDManager {
    public static final String TAG = "ECIDManager";
    public static final int INVALID_PHOND_ID = -1;
    IECIDManager mService;

    /**
     * package private on purpose
     */
    ECIDManager(IECIDManager service, Context ctx) {
        mService = service;

    }

    public int getECIDPhoneId() {
        try {
            return mService.getECIDPhoneId();
        } catch (RemoteException e) {
            Log.e(TAG, "[getECIDPhoneId] RemoteException");
        }
        return INVALID_PHOND_ID;
    }

    public LgeSimInfo getECIDSimInfo(){
        try {
            return mService.getECIDSimInfo();
        } catch (RemoteException e) {
            Log.e(TAG, "[getECIDSimInfo] RemoteException");
        }
        return null;
    }

    public boolean hasLteMode() {
        try {
            return mService.hasLteMode();
        } catch (RemoteException e) {
            Log.e(TAG, "[hasLteMode] RemoteException");
        }
        return false;
    }

    public boolean hasCBDefaultOn() {
        try {
            return mService.hasCBDefaultOn();
        } catch (RemoteException e) {
            Log.e(TAG, "[hasCBDefaultOn] RemoteException");
        }
        return false;
    }

    public List<String> getCBChannelList() {
        try {
            return mService.getCBChannelList();
        } catch (RemoteException e) {
            Log.e(TAG, "[getCBChannelList] RemoteException");
        }
        return null;
    }

    public List<String> getCBChannelNameList() {
        try {
            return mService.getCBChannelNameList();
        } catch (RemoteException e) {
            Log.e(TAG, "[getCBChannelNameList] RemoteException");
        }
        return null;
    }

    public String getBrowserHomePager() {
        try {
            return mService.getBrowserHomePager();
        } catch (RemoteException e) {
            Log.e(TAG, "[getBrowserHomePager] RemoteException");
        }
        return null;
    }

    public List<Bookmark> getBookmark() {
        try {
            return mService.getBookmark();
        } catch (RemoteException e) {
            Log.e(TAG, "[getBookmark] RemoteException");
        }
        return null;
    }

    public boolean enableDataConsumptionWwarning() {
        try {
            return mService.enableDataConsumptionWwarning();
        } catch (RemoteException e) {
            Log.e(TAG, "[enableDataConsumptionWwarning] RemoteException");
        }
        return false;
    }

    public String getDataWarningNotification() {
        try {
            return mService.getDataWarningNotification();
        } catch (RemoteException e) {
            Log.e(TAG, "[getDataWarningNotification] RemoteException");
        }
        return null;
    }

    public boolean voiceMailEditable() {
        try {
            return mService.voiceMailEditable();
        } catch (RemoteException e) {
            Log.e(TAG, "[voiceMailEditable] RemoteException");
        }
        return false;
    }

    public boolean voiceMailRoamingEditable() {
        try {
            return mService.voiceMailRoamingEditable();
        } catch (RemoteException e) {
            Log.e(TAG, "[voiceMailRoamingEditable] RemoteException");
        }
        return false;
    }

    public boolean disableClirValue() {
        try {
            return mService.disableClirValue();
        } catch (RemoteException e) {
            Log.e(TAG, "[disableClirValue] RemoteException");
        }
        return false;
    }

    public EmailSettingsInfo getEmailSettingsInfo() {
        try {
            return mService.getEmailSettingsInfo();
        } catch (RemoteException e) {
            Log.e(TAG, "[getEmailSettingsInfo] RemoteException");
        }
        return null;
    }

    public EmailSettingsProtocol getEmailSettingsProtocl() {
        try {
            return mService.getEmailSettingsProtocl();
        } catch (RemoteException e) {
            Log.e(TAG, "[getEmailSettingsProtocl] RemoteException");
        }
        return null;
    }

    public List<EmailServerProvider> getEmailServerProvider() {
        try {
            return mService.getEmailServerProvider();
        } catch (RemoteException e) {
            Log.e(TAG, "[getEmailServerProvider] RemoteException");
        }
        return null;
    }

    public int getDefaultContactPath() {
        try {
            return mService.getDefaultContactPath();
        } catch (RemoteException e) {
            Log.e(TAG, "[getDefaultContactPath] RemoteException");
        }
        return -1;
    }

    public boolean enableAMRWBGSM(){
        try {
            return mService.enableAMRWBGSM();
        } catch (RemoteException e) {
            Log.e(TAG, "[getBooleanValue] RemoteException");
        }
        return false;
    }

    public boolean enableAMRWBUMTS(){
        try {
            return mService.enableAMRWBUMTS();
        } catch (RemoteException e) {
            Log.e(TAG, "[getBooleanValue] RemoteException");
        }
        return false;
    }
    public boolean getBooleanValue(String key,String module){
        try {
            return mService.getBooleanValue(key,module);
        } catch (RemoteException e) {
            Log.e(TAG, "[getBooleanValue] RemoteException");
        }
        return false;
    }

    public int getIntValue(String key,String module){
        try {
            return mService.getIntValue(key,module);
        } catch (RemoteException e) {
            Log.e(TAG, "[getIntValue] RemoteException");
        }
        return -1;
    }

    public String getStringValue(String key,String module){
        try {
            return mService.getStringValue(key,module);
        } catch (RemoteException e) {
            Log.e(TAG, "[getStringValue] RemoteException");
        }
        return null;
    }

    public static class LgeSimInfo implements Parcelable {
        public static final Creator<LgeSimInfo> CREATOR
                = new Creator<LgeSimInfo>() {
            public LgeSimInfo createFromParcel(Parcel source) {
                return new LgeSimInfo(source);
            }

            public LgeSimInfo[] newArray(int size) {
                return new LgeSimInfo[size];
            }
        };
        public String mMcc;
        public String mMnc;
        public String mGid;
        public String mSpn;
        public String mImsi;
        public int mPhoneId;

        public LgeSimInfo(String mcc, String mnc, String gid, String spn, String imsi, int phoneId) {
            mMcc = mcc;
            mMnc = mnc;

            mGid = gid;
            mSpn = spn;
            mImsi = imsi;
            mPhoneId = phoneId;
        }

        public LgeSimInfo(String mcc, String mnc) {
            this(mcc, mnc, null, null, null, -1);
        }

        public LgeSimInfo(Parcel source) {
            readFromParcel(source);
        }

        public boolean isNull() {
            return TextUtils.isEmpty(mMcc) && TextUtils.isEmpty(mMnc);
        }

        public String getMcc() {
            return mMcc;
        }

        public void setMcc(String mMcc) {
            this.mMcc = mMcc;
        }

        public String getMnc() {
            return mMnc;
        }

        public void setMnc(String mMnc) {
            this.mMnc = mMnc;
        }

        public String getGid() {
            return mGid;
        }

        public void setGid(String mGid) {
            this.mGid = mGid;
        }

        public String getSpn() {
            return mSpn;
        }

        public void setSpn(String mSpn) {
            this.mSpn = mSpn;
        }

        public String getImsi() {
            return mImsi;
        }

        public void setImsi(String mImsi) {
            this.mImsi = mImsi;
        }

        public int getPhoneId() {
            return mPhoneId;
        }

        public void setPhoneId(int mPhoneId) {
            this.mPhoneId = mPhoneId;
        }

        @Override
        public int describeContents() {
            return 0;
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            if (mMcc == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(mMcc);
            }

            if (mMnc == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(mMnc);
            }

            if (mGid == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(mGid);
            }

            if (mSpn == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(mSpn);
            }

            if (mImsi == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(mImsi);
            }
            dest.writeInt(mPhoneId);
        }

        public void readFromParcel(Parcel source) {
            mMcc = source.readInt() > 0 ? source.readString() : null;
            mMnc = source.readInt() > 0 ? source.readString() : null;
            mGid = source.readInt() > 0 ? source.readString() : null;
            mSpn = source.readInt() > 0 ? source.readString() : null;
            mImsi = source.readInt() > 0 ? source.readString() : null;
            mPhoneId = source.readInt();
        }
    }

    public static class EmailSettingsInfo implements Parcelable {

        public static final Creator<EmailSettingsInfo> CREATOR
                = new Creator<EmailSettingsInfo>() {
            public EmailSettingsInfo createFromParcel(Parcel source) {
                return new EmailSettingsInfo(source);
            }

            public EmailSettingsInfo[] newArray(int size) {
                return new EmailSettingsInfo[size];
            }
        };
        public String notification;
        public String signature;
        public String espMode;
        public String contactSync;
        public String calendarSync;
        public String tasksSync;
        public String smsSync;

        public EmailSettingsInfo() {
            this.notification = null;
            this.signature = null;
            this.espMode = null;
            this.contactSync = null;
            this.calendarSync = null;
            this.tasksSync = null;
            this.smsSync = null;
        }

        public EmailSettingsInfo(Parcel source) {
            readFromParcel(source);
        }

        public String getNotification() {
            return notification;
        }

        public void setNotification(String notification) {
            this.notification = notification;
        }

        public String getSignature() {
            return signature;
        }

        public void setSignature(String signature) {
            this.signature = signature;
        }

        public String getEspMode() {
            return espMode;
        }

        public void setEspMode(String espMode) {
            this.espMode = espMode;
        }

        public String getContactSync() {
            return contactSync;
        }

        public void setContactSync(String contactSync) {
            this.contactSync = contactSync;
        }

        public String getCalendarSync() {
            return calendarSync;
        }

        public void setCalendarSync(String calendarSync) {
            this.calendarSync = calendarSync;
        }

        public String getTasksSync() {
            return tasksSync;
        }

        public void setTasksSync(String tasksSync) {
            this.tasksSync = tasksSync;
        }

        public String getSmsSync() {
            return smsSync;
        }

        public void setSmsSync(String smsSync) {
            this.smsSync = smsSync;
        }

        @Override
        public int describeContents() {
            return 0;
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            if (notification == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(notification);
            }

            if (signature == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(signature);
            }

            if (espMode == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(espMode);
            }

            if (contactSync == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(contactSync);
            }

            if (calendarSync == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(calendarSync);
            }

            if (tasksSync == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(tasksSync);
            }

            if (smsSync == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(smsSync);
            }
        }

        public void readFromParcel(Parcel source) {
            notification = source.readInt() > 0 ? source.readString() : null;
            signature = source.readInt() > 0 ? source.readString() : null;
            espMode = source.readInt() > 0 ? source.readString() : null;
            contactSync = source.readInt() > 0 ? source.readString() : null;
            calendarSync = source.readInt() > 0 ? source.readString() : null;
            tasksSync = source.readInt() > 0 ? source.readString() : null;
        }
    }

    public static class EmailSettingsProtocol implements Parcelable {

        public static final Creator<EmailSettingsProtocol> CREATOR
                = new Creator<EmailSettingsProtocol>() {
            public EmailSettingsProtocol createFromParcel(Parcel source) {
                return new EmailSettingsProtocol(source);
            }

            public EmailSettingsProtocol[] newArray(int size) {
                return new EmailSettingsProtocol[size];
            }
        };
        public String syncRoaming;
        public String syncInterval;
        public String popDeletePolicy;
        public String easProxy;
        public String updateScheduleInPeak;
        public String updateScheduleOffPeak;
        public EmailSettingsProtocol(){
            this.syncRoaming =null;
            this.syncInterval =null;
            this.popDeletePolicy = null;
            this.easProxy = null;
            this.updateScheduleInPeak = null;
            this.updateScheduleOffPeak = null;
        }

        public EmailSettingsProtocol(Parcel source) {
            readFromParcel(source);
        }

        public String getPopDeletePolicy() {
            return popDeletePolicy;
        }

        public void setPopDeletePolicy(String popDeletePolicy) {
            this.popDeletePolicy = popDeletePolicy;
        }

        public String getSyncRoaming() {
            return syncRoaming;
        }

        public void setSyncRoaming(String syncRoaming) {
            this.syncRoaming = syncRoaming;
        }

        public String getSyncInterval() {
            return syncInterval;
        }

        public void setSyncInterval(String syncInterval) {
            this.syncInterval = syncInterval;
        }

        public String getEasProxy() {
            return easProxy;
        }

        public void setEasProxy(String easProxy) {
            this.easProxy = easProxy;
        }

        public String getUpdateScheduleInPeak() {
            return updateScheduleInPeak;
        }

        public void setUpdateScheduleInPeak(String updateScheduleInPeak) {
            this.updateScheduleInPeak = updateScheduleInPeak;
        }

        public String getUpdateScheduleOffPeak() {
            return updateScheduleOffPeak;
        }

        public void setUpdateScheduleOffPeak(String updateScheduleOffPeak) {
            this.updateScheduleOffPeak = updateScheduleOffPeak;
        }

        @Override
        public String toString(){
            return "EmailSettingsProtocol,syncRoaming:"+syncRoaming
                    +" syncInterval:"+syncInterval
                    +" popDeletePolicy:"+popDeletePolicy
                    +" easProxy:"+easProxy
                    +" updateScheduleInPeak:"+updateScheduleInPeak
                    +" updateScheduleOffPeak:"+updateScheduleOffPeak;

        }

        @Override
        public int describeContents() {
            return 0;
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            if (syncRoaming == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(syncRoaming);
            }
            if (syncInterval == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(syncInterval);
            }

            if (popDeletePolicy == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(popDeletePolicy);
            }

            if (easProxy == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(easProxy);
            }

            if (updateScheduleInPeak == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(updateScheduleInPeak);
            }

            if (updateScheduleOffPeak == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(updateScheduleOffPeak);
            }
        }

        public void readFromParcel(Parcel source) {
            syncRoaming = source.readInt() > 0 ? source.readString() : null;
            syncInterval = source.readInt() > 0 ? source.readString() : null;
            popDeletePolicy = source.readInt() > 0 ? source.readString() : null;
            easProxy = source.readInt() > 0 ? source.readString() : null;
            updateScheduleInPeak = source.readInt() > 0 ? source.readString() : null;
            updateScheduleOffPeak = source.readInt() > 0 ? source.readString() : null;
        }
    }

    public static class EmailServerProvider implements Parcelable {

        public static final Creator<EmailServerProvider> CREATOR
                = new Creator<EmailServerProvider>() {
            public EmailServerProvider createFromParcel(Parcel source) {
                return new EmailServerProvider(source);
            }

            public EmailServerProvider[] newArray(int size) {
                return new EmailServerProvider[size];
            }
        };
        public String address;
        public String domain;
        public String name;
        public String incomingAddress;
        public String incomingProtocol;
        public String incomingSecurity;
        public String incomingPort;
        public String incomingUsername;
        public String incomingPassword;
        public String outgoingAddress;
        public String smtpAuth;
        public String outgoingPort;
        public String outgoingSecurity;
        public String outgoingUsername;
        public String outgoingPassword;
        public EmailServerProvider(){
            this.address = null;
            this.domain = null;
            this.name = null;
            this.incomingAddress = null;
            this.incomingPassword = null;
            this.incomingSecurity = null;
            this.incomingPort = null;
            this.incomingUsername = null;
            this.incomingPassword = null;
            this.outgoingAddress = null;
            this.smtpAuth = null;
            this.outgoingPort = null;
            this.outgoingSecurity = null;
            this.outgoingUsername = null;
            this.outgoingPassword = null;


        }

        public EmailServerProvider(Parcel source) {
            readFromParcel(source);
        }

        public String getAddress() {
            return address;
        }

        public void setAddress(String address) {
            this.address = address;
        }

        public String getDomain() {
            return domain;
        }

        public void setDomain(String domain) {
            this.domain = domain;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getIncomingAddress() {
            return incomingAddress;
        }

        public void setIncomingAddress(String incomingAddress) {
            this.incomingAddress = incomingAddress;
        }

        public String getIncomingProtocol() {
            return incomingProtocol;
        }

        public void setIncomingProtocol(String incomingProtocol) {
            this.incomingProtocol = incomingProtocol;
        }

        public String getIncomingSecurity() {
            return incomingSecurity;
        }

        public void setIncomingSecurity(String incomingSecurity) {
            this.incomingSecurity = incomingSecurity;
        }

        public String getIncomingPort() {
            return incomingPort;
        }

        public void setIncomingPort(String incomingPort) {
            this.incomingPort = incomingPort;
        }

        public String getIncomingUsername() {
            return incomingUsername;
        }

        public void setIncomingUsername(String incomingUsername) {
            this.incomingUsername = incomingUsername;
        }

        public String getIncomingPassword() {
            return incomingPassword;
        }

        public void setIncomingPassword(String incomingPassword) {
            this.incomingPassword = incomingPassword;
        }

        public String getOutgoingAddress() {
            return outgoingAddress;
        }

        public void setOutgoingAddress(String outgoingAddress) {
            this.outgoingAddress = outgoingAddress;
        }

        public String getOutgoingSecurity() {
            return outgoingSecurity;
        }

        public void setOutgoingSecurity(String outgoingSecurity) {
            this.outgoingSecurity = outgoingSecurity;
        }

        public String getOutgoingPort() {
            return outgoingPort;
        }

        public void setOutgoingPort(String outgoingPort) {
            this.outgoingPort = outgoingPort;
        }

        public String getOutgoingUsername() {
            return outgoingUsername;
        }

        public void setOutgoingUsername(String outgoingUsername) {
            this.outgoingUsername = outgoingUsername;
        }

        public String getOutgoingPassword() {
            return outgoingPassword;
        }

        public void setOutgoingPassword(String outgoingPassword) {
            this.outgoingPassword = outgoingPassword;
        }

        public String isSmtpAuth() {
            return smtpAuth;
        }

        public void setSmtpAuth(String smtpAuth) {
            this.smtpAuth = smtpAuth;
        }

        @Override
        public String toString(){
            return "EmailServerProvider,address:"+address
                    +" domain:"+domain
                    +" name:"+name
                    +" incomingAddress:"+incomingAddress
                    +" incomingProtocol:"+incomingProtocol
                    +" incomingSecurity:"+incomingSecurity
                    +" incomingPort:"+incomingPort
                    +" incomingUsername:"+incomingUsername
                    +" incomingPassword:"+incomingPassword
                    +" outgoingAddress:"+outgoingAddress
                    +" smtpAuth:"+smtpAuth
                    +" outgoingPort:"+outgoingPort
                    +" outgoingSecurity:"+outgoingSecurity
                    +" outgoingUsername:"+outgoingUsername
                    +" outgoingPassword:"+outgoingPassword;
        }

        @Override
        public int describeContents() {
            return 0;
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            if (address == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(address);
            }

            if (domain == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(domain);
            }

            if (name == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(name);
            }

            if (incomingAddress == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(incomingAddress);
            }

            if (incomingProtocol == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(incomingProtocol);
            }

            if (incomingSecurity == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(incomingSecurity);
            }

            if (incomingPort == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(incomingPort);
            }

            if (incomingUsername == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(incomingUsername);
            }

            if (incomingPassword == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(incomingPassword);
            }

            if (outgoingAddress == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(outgoingAddress);
            }

            if (smtpAuth == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(smtpAuth);
            }

            if (outgoingSecurity == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(outgoingSecurity);
            }

            if (outgoingPort == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(outgoingPort);
            }

            if (outgoingUsername == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(outgoingUsername);
            }

            if (outgoingPassword == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(outgoingPassword);
            }
        }

        public void readFromParcel(Parcel source) {
            address = source.readInt() > 0 ? source.readString() : null;
            domain = source.readInt() > 0 ? source.readString() : null;
            name = source.readInt() > 0 ? source.readString() : null;

            incomingAddress = source.readInt() > 0 ? source.readString() : null;
            incomingProtocol = source.readInt() > 0 ? source.readString() : null;
            incomingSecurity = source.readInt() > 0 ? source.readString() : null;
            incomingPort = source.readInt() > 0 ? source.readString() : null;
            incomingUsername = source.readInt() > 0 ? source.readString() : null;
            incomingPassword = source.readInt() > 0 ? source.readString() : null;

            outgoingAddress = source.readInt() > 0 ? source.readString() : null;
            smtpAuth = source.readInt() > 0 ? source.readString() : null;
            outgoingSecurity = source.readInt() > 0 ? source.readString() : null;
            outgoingPort = source.readInt() > 0 ? source.readString() : null;
            outgoingUsername = source.readInt() > 0 ? source.readString() : null;
            outgoingPassword = source.readInt() > 0 ? source.readString() : null;
        }
    }

    public static class Bookmark implements Parcelable {

        public static final Creator<Bookmark> CREATOR
                = new Creator<Bookmark>() {
            public Bookmark createFromParcel(Parcel source) {
                return new Bookmark(source);
            }
            public Bookmark[] newArray(int size) {
                return new Bookmark[size];
            }
        };
        public String mName;
        public String mUrl;
        public int mRead_only;

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

        public Bookmark(Parcel source) {
            readFromParcel(source);
        }

        public int getRead_only() {
            return mRead_only;
        }

        public void setRead_only(int read_only) {
            mRead_only = read_only;
        }

        public String getUrl() {
            return mUrl;
        }

        public void setUrl(String url) {
            mUrl = url;
        }

        public String getName() {
            return mName;
        }

        public void setName(String name) {
            mName = name;
        }

        @Override
        public int describeContents() {
            return 0;
        }

        @Override
        public void writeToParcel(Parcel dest, int flags) {
            if (mName == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(mName);
            }

            if (mUrl == null) {
                dest.writeInt(0);
            } else {
                dest.writeInt(1);
                dest.writeString(mUrl);
            }

            dest.writeInt(mRead_only);
        }

        public void readFromParcel(Parcel source) {
            mName = source.readInt() > 0 ? source.readString() : null;
            mUrl = source.readInt() > 0 ? source.readString() : null;
            mRead_only = source.readInt();
        }
    }
}
