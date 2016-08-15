/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
/*
 * Copyright (C) 2006 The Android Open Source Project
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


import android.app.IECIDManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.os.WorkSource;
import android.provider.Settings;
import android.text.TextUtils;
import android.text.format.Time;
import android.text.format.DateFormat;
import android.util.ArrayMap;
import android.util.KeyValueListParser;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Locale;
import java.util.Random;
import java.util.TimeZone;
import java.util.TreeSet;
import com.android.server.SystemService;
import android.app.ECIDManager;
import android.app.ECIDManager.LgeSimInfo;
import com.android.server.ecid.utils.*;
import android.app.ECIDManager.EmailSettingsInfo;
import android.app.ECIDManager.EmailSettingsProtocol;
import android.app.ECIDManager.EmailServerProvider;
import android.app.ECIDManager.Bookmark;
import java.util.List;
import android.content.IntentFilter;
import com.android.internal.telephony.TelephonyIntents;
import com.android.internal.telephony.uicc.IccCardProxy;
import android.os.Looper;
import android.provider.Telephony;
import android.telephony.SubscriptionInfo;
import android.telephony.SubscriptionManager;
import android.telephony.TelephonyManager;
import com.android.internal.telephony.IccCardConstants;
import com.android.internal.telephony.Phone;
import com.android.internal.telephony.PhoneConstants;
import com.android.internal.telephony.PhoneFactory;
import com.android.server.ecid.utils.GeneralParserAttribute;

import static com.huaqin.ecidparser.utils.GeneralParserAttribute.ECID_FIRST_VALID_MCC;
import static com.huaqin.ecidparser.utils.GeneralParserAttribute.ECID_FIRST_VALID_MNC;

/// M: end

public class ECIDManagerService extends SystemService implements GeneralParserAttribute {

    public static final String TAG = "ECIDManager";

    private final Context mContext;
    private final Handler mHandler;
    
    private static boolean mSlot1Absent = false;
    private static boolean mSlot2Absent = false;
    private static boolean hasLoadedOtherNotBasedSim = false;
    private static boolean hasLoadedGPRIWithSim = false;

    public static final int MSG_PASER_GPRI_NONE_RELATED_SIM = 0;
    public static final int MSG_PARSER_GPRI_WITH_SIM = 1;

    private static int currentParserSlotId = PhoneConstants.SIM_ID_1 ;
    private LgeSimInfo currentSimIno = null;
    private SubscriptionInfo currentSub = null;
    private static String mCurrentMccMnc = null;
    private  LgeSimInfo simInfo = null;
    public static HashMap<String,String> mLteReadyMap = new HashMap<String,String>();
    
    public static final String HAS_LOADED_OTHER_NOT_BASED_SIM = "has_loaded_not_based_sim";
    public static final String HAS_LOADED_GPRI_WITH_SIM = "has_loaded_gpri_with_sim";
    
    public ECIDManagerService(Context context) {
        super(context);
        mContext = context;
        Log.d(TAG, "ECIDManagerService");
        IntentFilter intentFilter = new IntentFilter(TelephonyIntents.ACTION_SIM_STATE_CHANGED);
        intentFilter.addAction(IccCardProxy.ACTION_INTERNAL_SIM_STATE_CHANGED);
        intentFilter.addAction(TelephonyIntents.ACTION_SUBINFO_RECORD_UPDATED);
        mContext.registerReceiver(sReceiver, intentFilter);
        mHandler = new LgeParserUpdateHandler(context.getMainLooper());
        
    }

    @Override
    public void onStart() {
        Log.d(TAG, "onStart");
        publishBinderService(Context.ECID_PARSER_SERVICE, mService);
        if(Settings.System.getInt(mContext.getContentResolver(), HAS_LOADED_OTHER_NOT_BASED_SIM,-1) != 1){
        //loadAndSetECIDProperty();
            mHandler.obtainMessage(MSG_PASER_GPRI_NONE_RELATED_SIM).sendToTarget();
        }
    }

    private final BroadcastReceiver sReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            Log.d(TAG, "action=" + action);
            if(hasLoadedGPRIWithSim){
                return;
            }
            if(action.equals(IccCardProxy.ACTION_INTERNAL_SIM_STATE_CHANGED)){

            }else if(action.equals(TelephonyIntents.ACTION_SIM_STATE_CHANGED)){
                String simStatus = intent.getStringExtra(IccCardConstants.INTENT_KEY_ICC_STATE);
                int slotId = intent.getIntExtra(PhoneConstants.SLOT_KEY, PhoneConstants.SIM_ID_1);
                Log.d(TAG,"simStatus=="+simStatus+" slotId=="+slotId);
                if(simStatus.equals(IccCardConstants.INTENT_VALUE_ICC_ABSENT)){
                    if(slotId == PhoneConstants.SIM_ID_1){
                        mSlot1Absent = true;
                    }else if(slotId == PhoneConstants.SIM_ID_2){
                        mSlot2Absent = true;
                    }
                }else if(simStatus.equals(IccCardConstants.INTENT_VALUE_ICC_LOADED)){
                    if(slotId == PhoneConstants.SIM_ID_1){
                        mSlot1Absent = false;
                    }else if(slotId == PhoneConstants.SIM_ID_2){
                        mSlot2Absent = false;
                    }
                }else{
                    Log.d(TAG,"this is not normal sim state(lock and so on)...ignore it");
                }
            }else if(action.equals(TelephonyIntents.ACTION_SUBINFO_RECORD_UPDATED)){
                if(!nullSimDevice() && !hsCorrectMccMnc()){
                    setCurrentSimInfo();
                }

            }
        }
    };

    private boolean nullSimDevice(){
        return mSlot1Absent && mSlot2Absent;
    }

    private void setCurrentSimInfo(){
        List<SubscriptionInfo> subs = SubscriptionManager.from(mContext)
                .getActiveSubscriptionInfoList();
        if(subs == null)
            return ;
        final TelephonyManager telephonyManager = (TelephonyManager)
                mContext.getSystemService(Context.TELEPHONY_SERVICE);
        final SubscriptionManager subscriptionManager = SubscriptionManager.from(mContext);
        final int numSlots = telephonyManager.getSimCount();
        Phone phone = null;

        if(numSlots ==1){
            Log.d(TAG,"signal sim ");
        }else if(numSlots ==2){
            Log.d(TAG,"dual sim ");
        }

        if(subs.size() == 1){
            currentParserSlotId =subs.get(0).getSimSlotIndex();
            currentSub = subs.get(0);
        }else if(subs.size()>1){
            currentParserSlotId =PhoneConstants.SIM_ID_1;
            for(int i=0 ;i<subs.size();i++){
                if(subs.get(i).getSimSlotIndex()==currentParserSlotId){
                    currentSub = subs.get(i);
                    break;
                }
            }
        }
        int subId = currentSub.getSubscriptionId();
        mCurrentMccMnc = telephonyManager.getSimOperator(subId);
        Log.d(TAG,"mccmnc =="+mCurrentMccMnc);
        if(!hsCorrectMccMnc()){
                return;
        }
        String mcc = mCurrentMccMnc.substring(0, 3);
        String mnc = mCurrentMccMnc.substring(3);
        String spn = telephonyManager.getSimOperatorNameForSubscription(subId);
        String imsi = telephonyManager.getSubscriberId(subId);
        String gid = telephonyManager.getGroupIdLevel1(subId);
        currentSimIno = new LgeSimInfo(mcc, mnc, gid, spn, imsi, currentParserSlotId);
        setSimProperty(currentSimIno);
        Log.d(TAG,"currentSimIno =="+currentSimIno.toString());

        mHandler.obtainMessage(MSG_PARSER_GPRI_WITH_SIM).sendToTarget();
    }

    private void setSimProperty(LgeSimInfo currentSimIno){
        SystemProperties.set(ECID_FIRST_VALID_MCC,currentSimIno.getMcc());
        SystemProperties.set(ECID_FIRST_VALID_MNC,currentSimIno.getMnc());
    }
    private final class LgeParserUpdateHandler extends Handler {
        public HashMap<String, String> mLteParserMap = new HashMap<String, String>();

        public LgeParserUpdateHandler(Looper looper) {
            super(looper, null, false);
        }

        @Override
        public void handleMessage(Message msg) {
            Log.d(TAG, "LgeParserUpdateHandler handleMessage" + msg.what);
            switch (msg.what) {
                case MSG_PASER_GPRI_NONE_RELATED_SIM:{
                    ParserUpdateThread updatorThread = new ParserUpdateThread(
                            new ParserUserObj(MSG_PASER_GPRI_NONE_RELATED_SIM, currentParserSlotId),
                            MSG_PASER_GPRI_NONE_RELATED_SIM);
                    updatorThread.start();
                    break;
                }
                case MSG_PARSER_GPRI_WITH_SIM:{
                    ParserUpdateThread updatorThread = new ParserUpdateThread(
                            new ParserUserObj(MSG_PARSER_GPRI_WITH_SIM, currentParserSlotId),
                            MSG_PARSER_GPRI_WITH_SIM);
                    updatorThread.start();
                    break;
                }
                default:
                    Log.d(TAG, "Unknown msg:" + msg.what);
            }
        }
    }
    
    private boolean hsCorrectMccMnc(){
     if(mCurrentMccMnc ==null || mCurrentMccMnc.isEmpty()){
      return false;
     }
     return true;
    }

    private class ParserUpdateThread extends Thread {

        private ParserUserObj mUserObj;
        private int mEventId;

        ParserUpdateThread(ParserUserObj userObj, int eventId) {
            mUserObj = userObj;
            mEventId = eventId;
        }

        @Override
        public void run() {
            switch (mEventId) {
                case MSG_PASER_GPRI_NONE_RELATED_SIM:
                    parserCommonGPRIWithOutSim();
                    break;
                case MSG_PARSER_GPRI_WITH_SIM:
                    parserSpecialGPRIWithSim();
                    break;
                default:
                    break;
            }
        }
    }

    private static class ParserUserObj {
        public int reason;
        public int slotId;

        ParserUserObj(int reason, int slotId) {
            this.reason = reason;
            this.slotId = slotId;
        }
    }

    private void parserCommonGPRIWithOutSim(){

    }

    private void parserSpecialGPRIWithSim(){
        LgeSimInfo simInfo = new LgeSimInfo("647","10");
		HashMap<String,String> mConfig = new HashMap<String,String>();
        mConfig = new HashMap<String,String>();
        Log.d(TAG,"Parser apkoverlay-Contacts3_JB:contacts_setting.xml");
        GeneralProfileParser lgeContactSettingParser =  new LgeContactSettingParser(this);
        lgeContactSettingParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_CONTACT_SETTINGS, mConfig, simInfo);
        Log.d(TAG,"mConfig=="+mConfig.toString());

        mConfig = new HashMap<String,String>();
        Log.d(TAG,"Parser apkoverlay-LGPartnerBookmarksProvider: browser_config.xml");
        ArrayList<Bookmark> mBookmarkList = new ArrayList<Bookmark>();
        LgeBrowserProfileParser lgeBrowserProfileParser =  new LgeBrowserProfileParser(this);
        lgeBrowserProfileParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_BROWSER_CONFIG, mConfig, simInfo);
        mBookmarkList = lgeBrowserProfileParser.getBoomarkList();
        Log.d(TAG,"mConfig=="+mConfig.toString());
        Log.d(TAG,"mBookmarkList=="+mBookmarkList.size());


        mConfig = new HashMap<String,String>();
        //mms special:<siminfo operator="default" country="" mcc="" mnc="" />
        Log.d(TAG,"Parser apkoverlay-LGMessage4:mms_config.xml");
        GeneralProfileParser lgeMmsConfigParser = new LgeMmsConfigParser(this);
        lgeMmsConfigParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_MMS_CONFIG, mConfig, simInfo);
        Log.d(TAG,"mConfig=="+mConfig.toString());
        mConfig = new HashMap<String,String>();

        Log.d(TAG,"should Parser LGTelephonyServices_config.xml, but no it,i will parser telephony_config.xml");
        GeneralProfileParser LgeConfigParser = new LgeConfigParser(this);
        LgeConfigParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_TELEPHONY_CONFIG, mConfig, simInfo);
        Log.d(TAG,"mConfig=="+mConfig.toString());


        mConfig = new HashMap<String,String>();
        Log.d(TAG,"Parser apkoverlay-LGCbReceiver4:cb_config.xml");
        ArrayList<String> mCBChList = new ArrayList<String>();
        ArrayList<String> mCBChNameList = new ArrayList<String>();
        LgeCBConfigParser lgeCbConfigParser = new LgeCBConfigParser(this);
        lgeCbConfigParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_CB_CONFIG, mConfig, simInfo);
        mCBChList = lgeCbConfigParser.getChannelList();
        mCBChNameList = lgeCbConfigParser.getChannelNameList();
        Log.d(TAG,"mConfig=="+mConfig.toString());
        if(mCBChList != null){
            Log.d(TAG,"mCBChList=="+mCBChList.toString());
        }
        if(mCBChNameList != null){
            Log.d(TAG,"mCBChNameList=="+mCBChNameList.toString());
        }


        mConfig = new HashMap<String,String>();
        Log.d(TAG,"Parser GPRI: telephony.xml");
        GeneralProfileParser lgeTelephonyParser = new LgeTelephonyParser(this);
        lgeTelephonyParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_TELEPHONY_PROFILE, mConfig, simInfo);
        Log.d(TAG,"mConfig=="+mConfig.toString());

        mConfig = new HashMap<String,String>();
        Log.d(TAG,"Parser GPRI- lteready.xml");
        GeneralProfileParser lgeLTEConfigParser = new LgeLTEConfigParser(this);
        lgeLTEConfigParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_LTE_READY_CONFIG, mConfig, simInfo);
        Log.d(TAG,"mConfig=="+mConfig.toString());

        mConfig = new HashMap<String,String>();
        Log.d(TAG,"Parser apkoverlay-LGSettingsProvider:settings_provider_config.xml");
        GeneralProfileParser lgeSettingsProviderParser = new LgeSettingsProviderParser(this);
        lgeSettingsProviderParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_SETTINGS_PROVIDER_CONFIG, mConfig, simInfo);
        Log.d(TAG,"mConfig=="+mConfig.toString());


        mConfig = new HashMap<String,String>();
        Log.d(TAG,"Parser apkoverlay-LGEmail4:email_config.xml");
        LgeEmailConfigParser lgeEmailConfigParser = new LgeEmailConfigParser(this);
        ArrayList<EmailServerProvider> mEmailAccountList = null;
        EmailSettingsInfo mEmailSettingsInfo = null;
        EmailSettingsProtocol mEmailSettingsProtocol = null;
        lgeEmailConfigParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_EMAIL_CONFIG, mConfig, simInfo);
        mEmailAccountList = lgeEmailConfigParser.getEmailAccountList();
        mEmailSettingsProtocol = lgeEmailConfigParser.getEmailProtocol();
        mEmailSettingsInfo = lgeEmailConfigParser.getEmailSettings();
        Log.d(TAG,"result,mEmailAccountList=="+mEmailAccountList.toString());
        Log.d(TAG,"result,mEmailSettingsProtocol=="+mEmailSettingsProtocol.toString());
        Log.d(TAG,"result,mEmailSettingsInfo=="+mEmailSettingsInfo.toString());
        Log.d(TAG,"mConfig=="+mConfig.toString());

        Log.d(TAG,"Parser gpri-LGEmail4:amrwb_gpri.xml");
        mConfig = new HashMap<String,String>();
        AmrwbSettingParser amrwbSettingParser =  new AmrwbSettingParser(this);
        amrwbSettingParser.loadLgProfile(GeneralParserAttribute.FILE_PATH_AMRWB_CONFIG,mConfig,simInfo);
        Log.d(TAG,"mConfig=="+mConfig.toString());
    }
    private final IBinder mService = new IECIDManager.Stub() {

        @Override
        public int getECIDPhoneId() {

            return 0;
        }

        @Override
        public boolean hasLteMode() {
            return false;
        }

        @Override
        public boolean hasCBDefaultOn() {
            Log.d(TAG, "hasCBDefaultOn");
            return false;
        }

        @Override
        public List<String> getCBChannelList() {
            Log.d(TAG, "getCBChannelList");
            ArrayList<String> test = new ArrayList<String>();
            test.add("haha");
            test.add("hehe");
            return test;
        }

        @Override
        public List<String> getCBChannelNameList() {
            Log.d(TAG, "getCBChannelNameList");
            return null;
        }

        @Override
        public String getBrowserHomePager() {
            Log.d(TAG, "getBrowserHomePager");
            return null;
        }

        @Override
        public List<Bookmark> getBookmark() {
            Log.d(TAG, "getBookmark");
            return null;
        }

        @Override
        public boolean enableDataConsumptionWwarning() {
            Log.d(TAG, "enableDataConsumptionWwarning");
            return false;
        }

        @Override
        public String getDataWarningNotification() {
            Log.d(TAG, "getDataWarningNotification");
            return null;
        }

        @Override
        public boolean voiceMailEditable() {
            Log.d(TAG, "voiceMailEditable");
            return false;
        }

        @Override
        public boolean voiceMailRoamingEditable() {
            Log.d(TAG, "voiceMailRoamingEditable");
            return false;
        }

        @Override
        public boolean disableClirValue() {
            Log.d(TAG, "disableClirValue");
            return false;
        }

        @Override
        public EmailSettingsInfo getEmailSettingsInfo() {
            Log.d(TAG, "getEmailSettingsInfo");
            return null;
        }

        @Override
        public EmailSettingsProtocol getEmailSettingsProtocl() {
            Log.d(TAG, "getEmailSettingsProtocl");
            return null;
        }

        @Override
        public List<EmailServerProvider> getEmailServerProvider() {
            Log.d(TAG, "getEmailServerProvider");
            return null;
        }

        @Override
        public int getDefaultContactPath() {
            Log.d(TAG, "getDefaultContactPath");
            return -1;
        }

        @Override
        public LgeSimInfo getECIDSimInfo() {
            Log.d(TAG, "getECIDSimInfo");
            return simInfo;
        }

        @Override
        public boolean enableAMRWBGSM() {
            Log.d(TAG, "enableAMRWBGSM");
            return false;
        }

        @Override
        public boolean enableAMRWBUMTS() {
            Log.d(TAG, "enableAMRWBUMTS");
            return false;
        }

        @Override
        public boolean getBooleanValue(String key,String module) {
            Log.d(TAG, "getBooleanValue");
            return false;
        }
        @Override
        public int getIntValue(String key,String module){
            Log.d(TAG, "getIntValue");
            return -1;
        }
        @Override
        public String getStringValue(String key,String module){
            Log.d(TAG, "getStringValue");
            return null;
        }
    };

}
