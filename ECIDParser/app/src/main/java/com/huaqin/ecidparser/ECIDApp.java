package com.huaqin.ecidparser;

import android.app.Application;
import android.content.Intent;
import android.os.UserHandle;
import android.util.Log;

import com.huaqin.ecidparser.utils.Utils;

import static android.R.attr.name;

/**
 * Created by shiguibiao on 16-8-8.
 */

public class ECIDApp extends Application {
    private static final String TAG =  Utils.APP;
    private static final String SERVICE_ACTION  = "com.huaqin.ecid.ECIDParserService";
    //parser flex propt
    public ECIDApp() {
    }

    @Override
    public void onCreate() {
        if (UserHandle.myUserId() == 0) {
            //flex.prop propertyParser
            //register sim subinfo state
            //start background services  parser
            Log.d(TAG,"ECIDApp start");
            Intent serviceIntent =new Intent();
            serviceIntent.setClass(this, ECIDParserService.class);
            startService(serviceIntent);
        }
    }
}
