package com.huaqin.ecidparser;

import android.content.Context;
import android.os.Handler;
import android.os.Message;
import android.util.Log;

import java.util.HashMap;

import static com.huaqin.ecidparser.GeneralProfileParser.TAG;

/**
 * Created by shiguibiao on 16-8-10.
 */

public class LgeParserUpdateHandler extends Handler {
    public Context mContext;

    public HashMap<String, String> mLteParserMap = new HashMap<String,String>();
    public LgeParserUpdateHandler(Context context){
        mContext = context;
        Log.d(TAG,"LgeParserUpdateHandler create");
    }

    @Override
    public void handleMessage(Message msg) {
        Log.d(TAG,"LgeParserUpdateHandler handleMessage"+msg.what);
        Log.d(TAG,"mLteParserMap"+mLteParserMap.toString());
        switch (msg.what) {
            case MSG_UPDATE_LTE_MODE_INFO:
                handleLteReady(msg.arg1);
            default:
                Log.d(TAG,"Unknown msg:" + msg.what);
        }
    }
    public void setInfoMap(HashMap<String, String> map){
        mLteParserMap = map;
    }

    private void handleLteReady(int phoneId){
    }
    private class ParserUpdateThread extends Thread {
        public static final int SIM_ABSENT = 0;
        public static final int SIM_LOADED = 1;
        public static final int SIM_LOCKED = 2;
        public static final int SIM_READY  = 3;
        public static final int SIM_NO_CHANGED = 4;

        private ParserUserObj mUserObj;
        private int mEventId;

        ParserUpdateThread(ParserUserObj userObj, int eventId) {
            mUserObj = userObj;
            mEventId = eventId;
        }

        @Override
        public void run() {
            switch (mEventId) {

                default:
                    break;
            }
        }
    }

    private static class ParserUserObj {
        public String reason;
        public int slotId;

        ParserUserObj(String reason, int slotId) {
            this.reason = reason;
            this.slotId = slotId;
        }
    };
}
