package com.huaqin.ecidparser;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import com.huaqin.ecidparser.amrwb.AmrwbParserAttribute;
import com.huaqin.ecidparser.bookmarks.Bookmark;
import com.huaqin.ecidparser.email.EmailServerProvider;
import com.huaqin.ecidparser.email.EmailSettingsInfo;
import com.huaqin.ecidparser.email.EmailSettingsProtocol;
import com.huaqin.ecidparser.utils.GeneralParserAttribute;
import com.huaqin.ecidparser.utils.LgeMccMncSimInfo;
import com.huaqin.ecidparser.utils.Utils;
import android.app.ECIDManager;

import java.util.ArrayList;
import java.util.HashMap;
public class MainActivity extends Activity {
    private static final String TAG = Utils.APP;    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        LgeMccMncSimInfo mSimInfo = new LgeMccMncSimInfo("647","10");
        HashMap<String, String> mConfig = new HashMap<String,String>();
        TextView tv = (TextView)findViewById(R.id.textView);
        ECIDManager ecid = (ECIDManager) getSystemService(Context.ECID_PARSER_SERVICE);
        tv.setText(ecid.getCBChannelList().toString());
        //init_LGE_AutoProfile(mSimInfo,mConfig);
    }

    private void init_LGE_AutoProfile(LgeMccMncSimInfo simInfo, HashMap<String, String> mConfig)
    {

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

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }
}
