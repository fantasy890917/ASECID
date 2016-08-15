package com.huaqin.ecidparser;

import android.content.Context;
import android.util.Log;

import com.huaqin.ecidparser.email.EmailParserAttribute;
import com.huaqin.ecidparser.email.EmailServerProvider;
import com.huaqin.ecidparser.email.EmailSettingsInfo;
import com.huaqin.ecidparser.email.EmailSettingsProtocol;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.ArrayList;

public class LgeEmailConfigParser extends GeneralProfileParser implements EmailParserAttribute {

	private final static String TAG = Utils.APP+LgeEmailConfigParser.class.getSimpleName();;
	private Context mContext;
    private ArrayList<EmailServerProvider> mEmailAccountList = null;
    private EmailSettingsInfo mEmailSettingsInfo = null;
    private EmailSettingsProtocol mEmailSettingsProtocol = null;
    private EmailServerProvider mEmailAccount = null;
	public LgeEmailConfigParser(Context context) {
		super(context);
		mContext = context;
	}

    /**
     * This method will be called whenever the parser meets &lt;Profile&gt;
     *
     * @param parser XmlPullParser
     * @return The ProfileData object
     */
    protected ProfileData readProfile(XmlPullParser parser) throws XmlPullParserException, IOException {

        NameValueProfile p = new NameValueProfile();
        Log.d(TAG,"[readProfile]name="+parser.getName()+" text="+parser.getText());

        while (ELEMENT_NAME_SIMINFO.equals(parser.getName()) ||
                ELEMENT_NAME_FEATURESET.equals(parser.getName())) {
            nextElement(parser);
        }
        while (parser.getName() != null
                &&(!parser.getName().equals(ELEMENT_NAME_PROFILE))) {
            String tag = parser.getName();
            Log.d(TAG, "[readProfile]tag=" + tag);

            switch (tag) {
                case ELEMENT_NAME_SETTINGS: {
                    mEmailSettingsInfo = new EmailSettingsInfo();
                    break;
                }
                case ELEMENT_NAME_PROTOCOL:  {
                    mEmailSettingsProtocol = new EmailSettingsProtocol();
                    mEmailSettingsProtocol.setSyncRoaming(parser.getAttributeValue(null, ATTR_NAME_SYNC_ROAMING));
                    mEmailSettingsProtocol.setSyncInterval(parser.getAttributeValue(null, ATTR_NAME_SYNC_INTERVAL));
                    mEmailSettingsProtocol.setEasProxy(parser.getAttributeValue(null, ATTR_NAME_EASPROXY));
                    mEmailSettingsProtocol.setPopDeletePolicy(parser.getAttributeValue(null, ATTR_NAME_POP_POLICY));
                    mEmailSettingsProtocol.setUpdateScheduleInPeak(parser.getAttributeValue(null, ATTR_NAME_IN_PEAK));
                    mEmailSettingsProtocol.setUpdateScheduleOffPeak(parser.getAttributeValue(null, ATTR_NAME_OFF_PEAK));
                    Log.d(TAG, "[readProfile][ELEMENT_NAME_PROTOCOL]=" + mEmailSettingsProtocol);
                    break;
                }
                case ELEMENT_NAME_NOTIFICATION: {
                    String noti_enable = parser.getAttributeValue(null, ATTR_NAME_ENABLE);
                    mEmailSettingsInfo.setNotification(noti_enable);
                    Log.d(TAG, "[readProfile][ELEMENT_NAME_NOTIFICATION]=" + noti_enable);
                    break;
                }
                case ELEMENT_NAME_SIGNATURE: {
                    String enable = parser.getAttributeValue(null, ATTR_NAME_ENABLE);
                    if("true".equals(enable)){
                        int type = parser.next();
                        if (type == XmlPullParser.TEXT) {
                            String value = parser.getText();
                            if(!Utils.isEmpty(value)){
                                mEmailSettingsInfo.setSignature(value);
                                Log.d(TAG, "[readProfile] ELEMENT_NAME_SIGNATURE:" + value);
                            }

                        }
                    }
                    break;
                }
                case ELEMENT_NAME_ESP: {
                    String noti_enable = parser.getAttributeValue(null, ATTR_NAME_MODE);
                    mEmailSettingsInfo.setEspMode(noti_enable);
                    Log.d(TAG, "[readProfile][ELEMENT_NAME_ESP]=" + noti_enable);
                    break;
                }
                case ELEMENT_NAME_CALENDAR: {
                    String noti_enable = parser.getAttributeValue(null, ATTR_NAME_SYNC);
                    mEmailSettingsInfo.setCalendarSync(noti_enable);
                    Log.d(TAG, "[readProfile][ELEMENT_NAME_CALENDAR]=" + noti_enable);
                    break;
                }
                case ELEMENT_NAME_CONTACT: {
                    String noti_enable = parser.getAttributeValue(null, ATTR_NAME_SYNC);
                    mEmailSettingsInfo.setContactSync(noti_enable);
                    Log.d(TAG, "[readProfile][ELEMENT_NAME_CONTACT]=" + noti_enable);
                    break;
                }
                case ELEMENT_NAME_TASKS: {
                    String noti_enable = parser.getAttributeValue(null, ATTR_NAME_SYNC);
                    mEmailSettingsInfo.setTasksSync(noti_enable);
                    Log.d(TAG, "[readProfile][ELEMENT_NAME_TASKS]=" + noti_enable);
                    break;
                }
                case ELEMENT_NAME_PROVIDERS:{
                    mEmailAccountList = new ArrayList<EmailServerProvider>();
                }
                case ELEMENT_NAME_PROVIDER_ITEM:{
                    mEmailAccount = new EmailServerProvider();
                    String domain = parser.getAttributeValue(null, ATTR_NAME_DOMAIN);
                    String email = parser.getAttributeValue(null, ATTR_NAME_EMAIL);
                    String name = parser.getAttributeValue(null, ATTR_NAME);
                    mEmailAccount.setDomain(domain);
                    mEmailAccount.setAddress(email);
                    mEmailAccount.setName(name);
                    break;
                }
                case ELEMENT_NAME_INCOMING:{
                    String incomingAddress = parser.getAttributeValue(null, ATTR_NAME_ADDRESS);
                    String incomingProtocol = parser.getAttributeValue(null, ATTR_NAME_PROTOCOL);
                    String incomingSecurity = parser.getAttributeValue(null, ATTR_NAME_SECURITY);
                    String incomingPort = parser.getAttributeValue(null, ATTR_NAME_PORT);
                    String incomingUsername = parser.getAttributeValue(null, ATTR_NAME_USERNAME);
                    String incomingPassword = parser.getAttributeValue(null, ATTR_NAME_PASSWORD);
                    mEmailAccount.setIncomingAddress(incomingAddress);
                    mEmailAccount.setIncomingProtocol(incomingProtocol);
                    mEmailAccount.setIncomingPort(incomingPort);
                    mEmailAccount.setIncomingSecurity(incomingSecurity);
                    if(!Utils.isEmpty(incomingUsername)){
                        mEmailAccount.setIncomingUsername(incomingUsername);
                    }
                    if(!Utils.isEmpty(incomingPassword)){
                        mEmailAccount.setIncomingPassword(incomingPassword);
                    }
                    break;
                }
                case ELEMENT_NAME_OUTGOING:{

                    String outgoingAddress = parser.getAttributeValue(null, ATTR_NAME_ADDRESS);
                    String smtpAuth = parser.getAttributeValue(null, ATTR_NAME_AUTH);
                    String outgoingSecurity = parser.getAttributeValue(null, ATTR_NAME_SECURITY);
                    String outgoingPort = parser.getAttributeValue(null, ATTR_NAME_PORT);
                    String outgoingUsername = parser.getAttributeValue(null, ATTR_NAME_USERNAME);
                    String outgoingPassword = parser.getAttributeValue(null, ATTR_NAME_PASSWORD);
                    mEmailAccount.setOutgoingAddress(outgoingAddress);
                    mEmailAccount.setSmtpAuth(smtpAuth);
                    mEmailAccount.setOutgoingSecurity(outgoingSecurity);
                    mEmailAccount.setOutgoingPort(outgoingPort);

                    if(!Utils.isEmpty(outgoingUsername)){
                        mEmailAccount.setOutgoingUsername(outgoingUsername);
                    }
                    if(!Utils.isEmpty(outgoingPassword)){
                        mEmailAccount.setOutgoingPassword(outgoingPassword);
                    }
                    if(mEmailAccount != null){
                        Log.d(TAG, "[readProfile][EMAIL ACCOUNT]=" + mEmailAccount);
                        mEmailAccountList.add(mEmailAccount);
                    }
                    break;
                }
                default:
                    // do nothing
                    break;

            }

            nextElement(parser);
        }

        return (ProfileData)p;
    }

    public ArrayList<EmailServerProvider> getEmailAccountList(){
        return mEmailAccountList;
    }

    public EmailSettingsInfo getEmailSettings(){
        return mEmailSettingsInfo;
    }

    public EmailSettingsProtocol getEmailProtocol(){
        return mEmailSettingsProtocol;
    }
}
