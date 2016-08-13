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
    public static final String TAG="ECIDManager";
    public static final int INVALID_PHOND_ID = -1;
    IECIDManager mService; 
    /**
     * package private on purpose
     */
    ECIDManager(IECIDManager service, Context ctx) {
        mService = service;

    }
    
    public String getValue(String name){  
            try {  
                return mService.getValue(name);  
            } catch (RemoteException e) {  
                Log.e(TAG, "[getValue] RemoteException");  
            }  
            return null;  
        }  
  
   public int update(String name, String value, int attribute) {  
            try {  
                return mService.update(name, value, attribute);  
            } catch (RemoteException e) {  
                Log.e(TAG, "[update] RemoteException");  
            }  
            return -1;  
        }  
    public int getECIDPhoneId(){
        try {
            return mService.getECIDPhoneId();
        } catch (RemoteException e) {
            Log.e(TAG, "[getECIDPhoneId] RemoteException");
        }
        return INVALID_PHOND_ID;
    }
    public boolean hasLteMode(){
        try {
            return mService.hasLteMode();
        } catch (RemoteException e) {
            Log.e(TAG, "[hasLteMode] RemoteException");
        }
        return false;
    }
    
    public boolean hasCBDefaultOn(){
        try {
            return mService.hasCBDefaultOn();
        } catch (RemoteException e) {
            Log.e(TAG, "[hasCBDefaultOn] RemoteException");
        }
        return false;
    }
    public List<String> getCBChannelList(){
        try {
            return mService.getCBChannelList();
        } catch (RemoteException e) {
            Log.e(TAG, "[getCBChannelList] RemoteException");
        }
        return null;
    }
    public List<String>  getCBChannelNameList(){
        try {
            return mService.getCBChannelNameList();
        } catch (RemoteException e) {
            Log.e(TAG, "[getCBChannelNameList] RemoteException");
        }
        return null;
    }
    
    public String getBrowserHomePager(){
        try {
            return mService.getBrowserHomePager();
        } catch (RemoteException e) {
            Log.e(TAG, "[getBrowserHomePager] RemoteException");
        }
        return null;
    }
    public List<BookmarkInfo> getBookmark(){
        try {
            return mService.getBookmark();
        } catch (RemoteException e) {
            Log.e(TAG, "[getBookmark] RemoteException");
        }
        return null;
    }
    
    public boolean enableDataConsumptionWwarning(){
        try {
            return mService.enableDataConsumptionWwarning();
        } catch (RemoteException e) {
            Log.e(TAG, "[enableDataConsumptionWwarning] RemoteException");
        }
        return false;
    }
    public String getDataWarningNotification(){
        try {
            return mService.getDataWarningNotification();
        } catch (RemoteException e) {
            Log.e(TAG, "[getDataWarningNotification] RemoteException");
        }
        return null;
    }
    public boolean voiceMailEditable(){
        try {
            return mService.voiceMailEditable();
        } catch (RemoteException e) {
            Log.e(TAG, "[voiceMailEditable] RemoteException");
        }
        return false;
    }
    public boolean voiceMailRoamingEditable(){
        try {
            return mService.voiceMailRoamingEditable();
        } catch (RemoteException e) {
            Log.e(TAG, "[voiceMailRoamingEditable] RemoteException");
        }
        return false;
    }
    public boolean disableClirValue(){
        try {
            return mService.disableClirValue();
        } catch (RemoteException e) {
            Log.e(TAG, "[disableClirValue] RemoteException");
        }
        return false;
    }

    public EmailSettingsInfo getEmailSettingsInfo(){
        try {
            return mService.getEmailSettingsInfo();
        } catch (RemoteException e) {
            Log.e(TAG, "[getEmailSettingsInfo] RemoteException");
        }
        return null;
    }

    public EmailSettingsProtocol getEmailSettingsProtocl(){
        try {
            return mService.getEmailSettingsProtocl();
        } catch (RemoteException e) {
            Log.e(TAG, "[getEmailSettingsProtocl] RemoteException");
        }
        return null;
    }

    public List<EmailServerProvider> getEmailServerProvider(){
        try {
            return mService.getEmailServerProvider();
        } catch (RemoteException e) {
            Log.e(TAG, "[getEmailServerProvider] RemoteException");
        }
        return null;
    }
    
    public int getDefaultContactPath(){
        try {
            return mService.getDefaultContactPath();
        } catch (RemoteException e) {
            Log.e(TAG, "[getDefaultContactPath] RemoteException");
        }
        return -1;
    }
        public static class LgeSimInfo implements Parcelable {
                @Override
                public int describeContents() {
                    return 0;
                }

                @Override
                public void writeToParcel(Parcel dest, int flags) {
                    
                }

                public void readFromParcel(Parcel source) {

                }

                public static final Creator<LgeSimInfo> CREATOR
                        = new Creator<LgeSimInfo>() {
                    public LgeSimInfo createFromParcel(Parcel source) {
                        return new LgeSimInfo(source);
                    }
                    public LgeSimInfo[] newArray(int size) {
                        return new LgeSimInfo[size];
                    }
                };

                private LgeSimInfo(Parcel source) {
                    readFromParcel(source);
                }
        }
        
        public static class EmailSettingsInfo implements Parcelable {
                @Override
                public int describeContents() {
                    return 0;
                }

                @Override
                public void writeToParcel(Parcel dest, int flags) {
                    
                }

                public void readFromParcel(Parcel source) {

                }

                public static final Creator<EmailSettingsInfo> CREATOR
                        = new Creator<EmailSettingsInfo>() {
                    public EmailSettingsInfo createFromParcel(Parcel source) {
                        return new EmailSettingsInfo(source);
                    }
                    public EmailSettingsInfo[] newArray(int size) {
                        return new EmailSettingsInfo[size];
                    }
                };

                private EmailSettingsInfo(Parcel source) {
                    readFromParcel(source);
                }
        }
        
        public static class EmailSettingsProtocol implements Parcelable {
                @Override
                public int describeContents() {
                    return 0;
                }

                @Override
                public void writeToParcel(Parcel dest, int flags) {
                    
                }

                public void readFromParcel(Parcel source) {

                }

                public static final Creator<EmailSettingsProtocol> CREATOR
                        = new Creator<EmailSettingsProtocol>() {
                    public EmailSettingsProtocol createFromParcel(Parcel source) {
                        return new EmailSettingsProtocol(source);
                    }
                    public EmailSettingsProtocol[] newArray(int size) {
                        return new EmailSettingsProtocol[size];
                    }
                };

                private EmailSettingsProtocol(Parcel source) {
                    readFromParcel(source);
                }
        }
        
        public static class EmailServerProvider implements Parcelable {
                @Override
                public int describeContents() {
                    return 0;
                }

                @Override
                public void writeToParcel(Parcel dest, int flags) {
                    
                }

                public void readFromParcel(Parcel source) {

                }

                public static final Creator<EmailServerProvider> CREATOR
                        = new Creator<EmailServerProvider>() {
                    public EmailServerProvider createFromParcel(Parcel source) {
                        return new EmailServerProvider(source);
                    }
                    public EmailServerProvider[] newArray(int size) {
                        return new EmailServerProvider[size];
                    }
                };

                private EmailServerProvider(Parcel source) {
                    readFromParcel(source);
                }
        }
        
        public static class BookmarkInfo implements Parcelable {
                @Override
                public int describeContents() {
                    return 0;
                }

                @Override
                public void writeToParcel(Parcel dest, int flags) {
                    
                }

                public void readFromParcel(Parcel source) {

                }

                public static final Creator<BookmarkInfo> CREATOR
                        = new Creator<BookmarkInfo>() {
                    public BookmarkInfo createFromParcel(Parcel source) {
                        return new BookmarkInfo(source);
                    }
                    public BookmarkInfo[] newArray(int size) {
                        return new BookmarkInfo[size];
                    }
                };

                private BookmarkInfo(Parcel source) {
                    readFromParcel(source);
                }
        }
}
