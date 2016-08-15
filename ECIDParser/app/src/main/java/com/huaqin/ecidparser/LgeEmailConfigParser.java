package com.huaqin.ecidparser;

import android.content.Context;
import android.text.TextUtils;
import android.util.Log;

import com.huaqin.ecidparser.bookmarks.Bookmark;
import com.huaqin.ecidparser.email.EEMAIL_AUTHENTICATION_TYPE;
import com.huaqin.ecidparser.email.EEMAIL_PROTOCOL_TYPE;
import com.huaqin.ecidparser.email.EmailParserAttribute;
import com.huaqin.ecidparser.email.OperatorConfigData.EmailServiceProvider;
import com.huaqin.ecidparser.email.OperatorConfigData.PreAccount;
import com.huaqin.ecidparser.email.OperatorConfigData.Setting;
import com.huaqin.ecidparser.email.OperatorConfigData.WelcomeMessage;
import com.huaqin.ecidparser.utils.ProfileData;
import com.huaqin.ecidparser.utils.Utils;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashMap;

public class LgeEmailConfigParser extends GeneralProfileParser implements EmailParserAttribute {

	private final static String TAG = Utils.APP+LgeEmailConfigParser.class.getSimpleName();;
	private Context mContext;


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
                case ELEMENT_NAME_READONLY: {
                    String value = parser.getAttributeValue(null, ATTR_VALUE);
                    p.setValue(tag, value);
                    Log.d(TAG, "[readProfile][READ_ONLY]=" + value);
                    break;
                }
                case ELEMENT_NAME_BOOKMARK: {
                    String editable = parser.getAttributeValue(null, ATTR_READONLY);
                    String title = parser.getAttributeValue(null, ATTR_NAME);
                    String url = parser.getAttributeValue(null, ATTR_URL);
                    if (editable != null) {
                        mBookmarkList.add(new Bookmark(title,url, Integer.parseInt(editable)));
                    } else {
                        mBookmarkList.add(new Bookmark(title,url, -1));
                    }
                    Log.d(TAG, "[readProfile][BOOKMARK TITLE]=" + title + " [URL]=" + url);
                    break;
                }
                case ELEMENT_NAME_HOMEPAGE: {
                    String value = parser.getAttributeValue(null, ATTR_VALUE);
                    p.setValue(tag, value);
                    Log.d(TAG, "[readProfile][HOMEPAGE]=" + value);
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

    protected void changeGpriValueFromLGE(HashMap<String, String> hashmap)
    {
        Log.d(TAG,"changeGpriValueFromLGE");
        /*
            <notification enabled="true" />
            <signature enabled="false" />
            <esp mode="0" />
            <protocol syncRoaming="false" syncInterval="-1" popDeletePolicy="0" easProxy="false" updateScheduleInPeak="0" updateScheduleOffPeak="0" />
            <contact sync="true" />
            <calendar sync="true" />
        */
        // not configured: updateScheduleInPeak="0" updateScheduleOffPeak="0"
        Setting setting = mData.getSetting();
        /*
        hashmap.put(flex.ID_ONESW_EMAIL_USE_CALENDAR_SYNC, setting.isCalendarSync()?"Yes":"No");
        hashmap.put(flex.ID_ONESW_EMAIL_USE_CONTACT_SYNC, setting.isContactSync()?"Yes":"No");
        hashmap.put(flex.ID_ONESW_EAMIL_NOTIFICATION, setting.isNotifyEnable()?"Yes":"No");
        hashmap.put(flex.ID_ONESW_EMAIL_SIGNATURE_ACTIVATED, setting.isSignatureEnable()?"Yes":"No");
        if (setting.isSignatureEnable()) {
            hashmap.put(flex.ID_ONESW_EMAIL_DEF_SIGNNATURE, setting.getSignature());
        }
        hashmap.put(flex.ID_ONESW_EMAIL_ESP_ENABLED, setting.isEspEnable()?"Yes":"No");
        hashmap.put(flex.ID_ONESW_GET_EAMIL_IN_ROAMING, setting.isSyncRoaming()?"Yes":"No");
        hashmap.put(flex.ID_ONESW_EMAIL_CHECK_INTERVAL, String.valueOf(setting.getSyncInterval()));
        hashmap.put(flex.ID_ONESW_EMAIL_DEL_POLICY_OF_POP3, String.valueOf(setting.getPopDeletePolicy()));
        */
        /*
            <provider domain="aliceadsl.fr" email="\@aliceadsl.fr" name="Alice" fulladdress_id="1">
                <incoming address="pop.aliceadsl.fr" protocol="pop3" port="110" security="0" username="" password="" />
                <outgoing address="smtp.aliceadsl.fr" auth="false" port="25" security="0" username="" password="" />
            </provider>
           */
        // not used: fulladdress_id
        ArrayList<EmailServiceProvider> emailServiceProviders = mData.getEmailServiceProvider();
        String preTag = "Email@Preset_Accounts_" ;
        for(int i = 1; i<= emailServiceProviders.size(); i++)
        {
            EmailServiceProvider esp = emailServiceProviders.get(i-1);

            String type_tag = preTag + i + "_Type";
            hashmap.put(type_tag, "provider") ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, type_tag = " + type_tag + " value = " + "provider");

            String domain_flag = preTag + i + "_Domain";
            hashmap.put(domain_flag, esp.getDomain()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, domain_flag = " + domain_flag + " value = " + esp.getDomain());

            String title_flag = preTag + i + "_Account_Title";
            hashmap.put(title_flag, esp.getDescription()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, domain_flag = " + domain_flag + " value = " + esp.getDescription());

            String email_flag = preTag + i + "_Email_Adress";
            hashmap.put(email_flag, esp.getEmailAddress()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, email_flag = " + email_flag + " value = " + esp.getEmailAddress());

            String incoming_protocol_flag = preTag + i + "_Incoming_Server_Protocol" ;
            hashmap.put(incoming_protocol_flag, esp.getSupportedProtocalType()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, incoming_protocol_flag = " + incoming_protocol_flag + " value = " + esp.getSupportedProtocalType());

            String incoming_address_flag = preTag + i + "_Incoming_Server_Address" ;
            hashmap.put(incoming_address_flag, esp.getIncomingServerAddress()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLG, incoming_address_flag = " + incoming_address_flag + " value = " + esp.getIncomingServerAddress());

            String incoming_security_flag = preTag + i + "_Incoming_Server_Security" ;
//            hashmap.put(incoming_security_flag, String.valueOf(esp.getNeedSecureConnectionForIncoming().swigValue())) ;
            hashmap.put(incoming_security_flag, esp.convertSecurityForm(esp.getSecurityForIncoming())) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, incoming_security_flag = " + incoming_security_flag + " value = " + esp.convertSecurityForm(esp.getSecurityForIncoming()));

            String incoming_port_flag = preTag + i + "_Incoming_Server_Port" ;
            hashmap.put(incoming_port_flag, String.valueOf(esp.getIncomingServerPortNumber())) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, incoming_port_flag = " + incoming_port_flag + " value = " + String.valueOf(esp.getIncomingServerPortNumber()));

            String incoming_user_flag = preTag + i + "_Incoming_User_Name" ;
            hashmap.put(incoming_user_flag, esp.getIncomingUsername()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, incoming_user_flag = " + incoming_user_flag + " value = " + esp.getIncomingUsername());

            String incoming_password_flag = preTag + i + "_Incoming_Password" ;
            hashmap.put(incoming_password_flag, esp.getIncomingPassword()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, incoming_password_flag = " + incoming_password_flag + " value = " + esp.getIncomingPassword());

            // the value in xml is true or false, but in EmailServiceProvider, it is a int value. So save it as int value.
            String outgoing_auth_flag = preTag + i + "_Outgoing_Server_Authentication" ;
            hashmap.put(outgoing_auth_flag, String.valueOf(esp.convertOnOffForm(esp.getAuthenticationType()))) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, outgoing_auth_flag = " + outgoing_auth_flag + " value = " + String.valueOf(esp.getAuthenticationType()));

            String outgoing_address_flag = preTag + i + "_Outgoing_Server_Address" ;
            hashmap.put(outgoing_address_flag, esp.getOutgoingServerAddress()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, outgoing_address_flag = " + outgoing_address_flag + " value = " + esp.getOutgoingServerAddress());

            String outgoing_security_flag = preTag + i + "_Outgoing_Server_Security" ;
            hashmap.put(outgoing_security_flag, esp.convertSecurityForm(esp.getSecurityForOutgoing())) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, outgoing_security_flag = " + outgoing_security_flag + " value = " + esp.convertSecurityForm(esp.getSecurityForOutgoing()));

            String outgoing_port_flag = preTag + i + "_Outgoing_Server_Port" ;
            hashmap.put(outgoing_port_flag, String.valueOf(esp.getOutgoingServerPortNumber())) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, outgoing_port_flag = " + outgoing_port_flag + " value = " + String.valueOf(esp.getOutgoingServerPortNumber()));

            String outgoing_user_flag = preTag + i + "_Outgoing_User_Name" ;
            hashmap.put(outgoing_user_flag, esp.getOutgoingUsername()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, outgoing_user_flag = " + outgoing_user_flag + " value = " + esp.getOutgoingUsername());

            String outgoing_password_flag = preTag + i + "_Outgoing_Password" ;
            hashmap.put(outgoing_password_flag, esp.getOutgoingPassword()) ;
            Log.d(TAG,"LgeEmailConfigParser:changeGpriValueFromLGE, outgoing_password_flag = " + outgoing_password_flag + " value = " + esp.getOutgoingPassword());
        }

        // not configured
        //PreAccount preAccount = mData.getPreAccount();
        //WelcomeMessage welcomMessage = mData.getWelcomeMessage();
    }
    /**
     * Parse Provider Tag information
     *
     * @param parser
     */
    private void parseProvidertag(DecorateParser parser) {
        String tag = parser.getName();
        if (tag !=null &&  tag.equals("providers")) {
            try {
                parseESP(parser);
            } catch (XmlPullParserException e) {
                Log.e(TAG, "XmlPullParserException : Check config xml parsing, startParse");
                Log.e(TAG, e.getMessage());
            } catch (IOException e) {
                Log.e(TAG, "IOException : Check config xml parsing, startParse");
                Log.e(TAG, e.getMessage());
            } catch (URISyntaxException e) {
                Log.e(TAG, "URISyntaxException : Check config xml parsing, startParse");
                Log.e(TAG, e.getMessage());
            }catch (Exception e) {
            	Log.e(TAG, "Exception");
            }
        }
    }


    private static String getXmlAttribute(Context context, DecorateParser xml,
            String name) {
        return xml.getAttributeValue(null, name);
    }

    private static boolean isXmlAttributeNullOrEmpty(String value) {
        if (value == null || "".equals(value) == true) {
            return true;
        }
        return false;
    }



    /**
     * Parse Account Tag information
     *
     * @param parser
     */
    private void parseAccounttag(DecorateParser parser) {
        Log.d(TAG, "parseAccounttag()");
        String tag = parser.getName();
        if (tag != null && tag.equals("account")) {
            try {
                parsePreAccount(parser);
            } catch (XmlPullParserException e) {
                Log.e(TAG, "XmlPullParserException : Check config xml parsing, startParse");
                Log.e(TAG, e.getMessage());
            } catch (IOException e) {
                Log.e(TAG,"IOException : Check config xml parsing, startParse");
                Log.e(TAG, e.getMessage());
            }catch (Exception e) {
            	Log.e(TAG, "Exception");
            }
        }
    }

    /**
     * Parse Settings Tag information
     *
     * @param parser
     */
    private void parseSettingstag(DecorateParser parser) {
        Log.d(TAG, "parseSettingstag()");
        String tag = parser.getName();

        if (tag != null && tag.equals("settings")) {
            try {
                parseSetting(parser);
            } catch (XmlPullParserException e) {
                Log.e(TAG,"XmlPullParserException : Check config xml parsing, startParse");
                Log.e(TAG, e.getMessage());
            } catch (IOException e) {
                Log.e(TAG, "IOException : Check config xml parsing, startParse");
                Log.e(TAG, e.getMessage());
            }catch (Exception e) {
            	Log.e(TAG, "Exception");
            }
        }
    }

    /**
     * Parse setting information
     *
     * @param parser
     * @throws XmlPullParserException
     * @throws IOException
     */
    private void parseSetting(DecorateParser parser)
            throws XmlPullParserException, IOException {
        int parseEvent = parser.getEventType();
        Setting setting = mData.getSetting();
        while (!(parseEvent == XmlPullParser.END_TAG && parser.getName() != null && parser.getName()
                .equals("settings"))) {
            Log.d(TAG, "parseSetting()--parseEvent="+parseEvent+" getName="+parser.getName());
            switch (parseEvent) {
            case DecorateParser.START_TAG:
                String tag = parser.getName();
                if (tag == null) {
                	Log.e(TAG, "tag is null");
                	return;
                }
                if (tag.equals("esp")) {
                    parseEspTag(parser, setting);
                } else if (tag.equals("protocol")) {
                    parseProtocolTag(parser, setting);
                } else if (tag.equals("notification")) {
                    parseNotificationTag(parser, setting);
                } else if (tag.equals("signature")) {
                    parseSignatureTag(parser, setting);
                } else if (tag.equals("calendar")) {
                    parseCalendarTag(parser, setting);
                } else if (tag.equals("contact")) {
                    parseContactTag(parser, setting);
                } else if (tag.equals("tasks")) {
                    parseTasksTag(parser, setting);
                    // LGE_CHANGE_SMS_SYNC_BEGIN sunghwa.woo 20140409 to support
                    // apk overlay
                } else if (tag.equals("sms")) {
                    parseSmsTag(parser, setting);
                }
                // LGE_CHANGE_SMS_SYNC_END sunghwa.woo 20140409
                break;
            default:
                break;
            }
            parseEvent = parser.next();
        }
    }

	 /**
     * Parse ESP Tag information
     *
     * @param parser
     * @param setting
     */
    private void parseEspTag(DecorateParser parser, Setting setting) {
        setting.espEnable = parser.getAttributeBooleanValue(null, "enabled",
                true);
        setting.espMode = parser.getAttributeIntValue(null, "mode", 0);
    }

    /**
     * Parse Protocol Tag information
     *
     * @param parser
     * @param setting
     */
    private void parseProtocolTag(DecorateParser parser, Setting setting) {

        setting.easSyncAmount = parser.getAttributeIntValue(null,
                "easSyncAmount", -1);
        boolean roamingDefaultVal = false;
        setting.syncRoaming = parser.getAttributeBooleanValue(null,
                "syncRoaming", roamingDefaultVal);
        setting.syncRoming = parser.getAttributeBooleanValue(null,
                "syncRoming", roamingDefaultVal);

        setting.syncInterval = parser.getAttributeIntValue(null,
                "syncInterval", -1);
        setting.popDeletePolicy = parser.getAttributeIntValue(
                null,
                "popDeletePolicy", -1);

        setting.smtpAuth = parser.getAttributeBooleanValue(null, "smtpAuth",
                true);
        setting.changeProtocolEnable = parser.getAttributeBooleanValue(null,
                "changeProtocol", true);
        setting.imapOperatorId = parser.getAttributeValue(null,
                "imapOperatorID");
        setting.easProxy = parser.getAttributeBooleanValue(null, "easProxy",
                false);
        /* rabbani.shaik@lge.com ,11, July 2012,AccountSettings -- [Start] */
        setting.emailDaystoSync = parser
                .getAttributeIntValue(
                        null,
                        "emailDaystoSync", -1);

        setting.maxEmailtoShow = parser
                .getAttributeIntValue(
                        null,
                        "maxEmailtoShow", -1);

        setting.updateScheduleInPeak = parser
                .getAttributeIntValue(
                        null,
                        "updateScheduleInPeak", -1);

        setting.updateScheduleOffPeak = parser
                .getAttributeIntValue(
                        null,
                        "updateScheduleOffPeak", -1);

        /* rabbani.shaik@lge.com ,11, July 2012,AccountSettings -- [End] */
        setting.messageSizeLimit = parser.getAttributeIntValue(null, "messageSizeLimit", -1);

    }

    /**
     * Parse Notification Tag information
     *
     * @param parser
     * @param setting
     */
    private void parseNotificationTag(DecorateParser parser, Setting setting) {
        setting.notifyEnable = parser.getAttributeBooleanValue(
                null,
                "enabled", false);
        setting.notifyVibrate = parser
                .getAttributeIntValue(
                        null,
                        "vibrate", -1);

    }

    /**
     * Parse Signature Tag
     *
     * @param parser
     * @param setting
     * @throws XmlPullParserException
     * @throws IOException
     */
    private void parseSignatureTag(DecorateParser parser, Setting setting)
            throws XmlPullParserException, IOException {

        // Signature is not only up to operator.xml.
        // Some operator wants to translate signature, so OperatorConfigBuilder
        // decides what signature will be used.
        // If you want use translate one, use @string/signaute_link and resource
        // overlay
        // - Add signuture string to res/value-xx
        // ex) <string name="sp_sprint_signature_NORMAL">Sent from my LG
        // smartphone</string>
        // - Add file in in resource overlay folder(ex.
        // res_overlay/XXX/res/values) and link <string name ="signaute_link">
        // to real signature.
        // ex) <string
        // name="signaute_link">@string/sp_sprint_signature_NORMAL</string>
        setting.signatureEnable = parser.getAttributeBooleanValue(null,
                "enabled", false );
        Log.d(TAG,"TAG="+parser.getName()+"Event="+parser.next()+" text="+parser.getText());
        if (DecorateParser.TEXT == parser.next()) {
            setting.signature = parser.getText();
        } else {
            setting.signature = "";
        }

    }

    /**
     * Parse setting information
     *
     * @param parser
     * @param setting
     */
    private void parseCalendarTag(DecorateParser parser, Setting setting) {
        Log.d(TAG,"parseCalendarTag");
        setting.calendarSync = parser.getAttributeBooleanValue(
                null,
                "sync", false);

        setting.calendarSyncAmount = parser
                .getAttributeIntValue(
                        null,
                        "amount",-1);

    }

    /**
     * Parse setting information
     *
     * @param parser
     * @param setting
     */
    private void parseContactTag(DecorateParser parser, Setting setting) {
        setting.contactSync = parser.getAttributeBooleanValue(
                null,
                "sync", false);

    }

    /* rabbani.shaik@lge.com ,11, July 2012,AccountSettings -- [Start] */
    /**
     * Parse setting information
     *
     * @param parser
     * @param setting
     */
    private void parseTasksTag(DecorateParser parser, Setting setting) {
        setting.tasksSync = parser.getAttributeBooleanValue(
                null,
                "sync", false);

    }

    /* rabbani.shaik@lge.com ,11, July 2012,AccountSettings -- [End] *//**
     *
     * /*rabbani.shaik@lge.com ,11, July 2012,AccountSettings -- [End]
     */
    // LGE_CHANGE_SMS_SYNC_BEGIN sunghwa.woo 20140409 to support apk overlay
    /**
     * Parse setting information
     *
     * @param parser
     * @param setting
     */
    private void parseSmsTag(DecorateParser parser, Setting setting) {
        setting.smsSync = parser.getAttributeBooleanValue(
                null,
                "sync",false);

    }

    // LGE_CHANGE_SMS_SYNC_END sunghwa.woo 20140409 to support apk overlay
    /**
     * Parse PreAccount
     *
     * @param parser
     * @throws XmlPullParserException
     * @throws IOException
     */
    private void parsePreAccount(DecorateParser parser)
            throws XmlPullParserException, IOException {
        PreAccount preAccount = mData.getPreAccount();
        preAccount.address = parser.getAttributeValue(null, "address");
        preAccount.domain = parser.getAttributeValue(null, "domain");
        preAccount.name = parser.getAttributeValue(null, "name");
        preAccount.desc = parser.getAttributeValue(null, "desc");

        int parseEvent = parser.getEventType();
        while (!(parseEvent == XmlPullParser.END_TAG && parser.getName()
                .equals("account"))) {
            switch (parseEvent) {
            case DecorateParser.START_TAG:
                String tag = parser.getName();
                if (tag.equals("incoming")) {
                    preAccount.incomingAddress = parser.getAttributeValue(null,
                            "address");
                    preAccount.incomingProtocol = parser.getAttributeValue(
                            null, "protocol");
                    preAccount.incomingSecurity = parser.getAttributeIntValue(
                            null, "security", 0);
                    preAccount.incomingPort = parser.getAttributeIntValue(null,
                            "port", -1);
                    preAccount.incomingUsername = parser.getAttributeValue(
                            null, "username");
                    preAccount.incomingPassword = parser.getAttributeValue(
                            null, "password");
                } else if (tag.equals("outgoing")) {
                    preAccount.outgoingAddress = parser.getAttributeValue(null,
                            "address");
                    preAccount.outgoingSecurity = parser.getAttributeIntValue(
                            null, "security", 0);
                    preAccount.outgoingPort = parser.getAttributeIntValue(null,
                            "port", -1);
                    preAccount.outgoingUsername = parser.getAttributeValue(
                            null, "username");
                    preAccount.outgoingPassword = parser.getAttributeValue(
                            null, "password");
                    preAccount.smtpAuth = parser.getAttributeBooleanValue(null,
                            "auth", true);
                }
                break;
            default:
                break;
            }
            parseEvent = parser.next();
        }
    }

    // basanta.behera@lge.com,18, July 2012, Start

    /**
     * Parse Welcome Message
     *
     * @param parser
     * @throws XmlPullParserException
     * @throws IOException
     */
    private void parseWelcomeMessage(DecorateParser parser)
            throws XmlPullParserException, IOException {
        WelcomeMessage welcomMessage = mData.getWelcomeMessage();

        int parseEvent = parser.getEventType();
        while (!(parseEvent == XmlPullParser.END_TAG && parser.getName()
                .equals("message"))) {
            switch (parseEvent) {
            case DecorateParser.START_TAG:
                String tag = parser.getName();
                if (tag.equals("from") && DecorateParser.TEXT == parser.next()) {
                    welcomMessage.from = parser.getText();
                } else if (tag.equals("name")
                        && DecorateParser.TEXT == parser.next()) {
                    welcomMessage.name = parser.getText();
                } else if (tag.equals("subject")
                        && DecorateParser.TEXT == parser.next()) {
                    welcomMessage.subject = parser.getText();
                } else if (tag.equals("body")
                        && DecorateParser.TEXT == parser.next()) {
                    welcomMessage.body = parser.getText();
                }
                break;
            default:
                break;
            }
            parseEvent = parser.next();
        }
    }

    /**
     * Parse Eamil Service Providers list
     *
     * @param xml
     * @throws XmlPullParserException
     * @throws IOException
     * @throws URISyntaxException
     */
    private void parseESP(DecorateParser xml) throws XmlPullParserException,
            IOException, URISyntaxException {
//        LGEmailLog.d(TAG, "parseESP()");
        ArrayList<EmailServiceProvider> emailServiceProviders = mData.getEmailServiceProvider();
        emailServiceProviders.clear(); // for delete lower priority profile's
                                       // esp
        EmailServiceProvider esp = null;
        int xmlEventType = xml.getEventType();
        String providerDomain = null;
        String pop3Address = null;
        String imapAddress = null;
        String easAddress = null;
        String smtpAddress = null;
        Short incomingSecurity;
        Short outcomingSecurity;
        String description = null;

        while (!(xmlEventType == XmlPullParser.END_TAG && xml.getName().equals(
                "providers"))) {
            String protocol;
            switch (xmlEventType) {
            case DecorateParser.START_TAG:
                String tag = xml.getName();
                if (tag.equals("provider")) {
                	//ltk modify because not accessible to EmailServiceProvider
                    esp =  mData.new EmailServiceProvider();
                    providerDomain = getXmlAttribute(mContext, xml, "domain");
                    esp.setDomain(providerDomain);
                    description = getXmlAttribute(mContext, xml, "name");
                    description = description.replace(" / Msn", ""); // ??? ????
                                                                     // ???.. ??
                                                                     // LGEmail
                                                                     // ??..
                    esp.setDescription(description);
                    esp.emailAddress = xml.getAttributeValue(null, "email");
                } else if (tag.equals("incoming") && esp != null) {
                    protocol = xml.getAttributeValue(null, "protocol");
                    esp.setSupportedProtocalType(protocol);
                    if (protocol.equalsIgnoreCase("imap")) {
                        imapAddress = getXmlAttribute(mContext, xml, "address");
                        if (false == isXmlAttributeNullOrEmpty(imapAddress)) {
                            esp.setIncomingServerAddressImap4(imapAddress);
                        }
                        esp.setIncomingProtocolType(EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_IMAP4);

                        // If IMAP4 port number is empty, then set default
                        // value.
                        String portNumberImap4 = getXmlAttribute(mContext, xml,
                                "port");
                        if (TextUtils.isEmpty(portNumberImap4)) {
                            esp.setIncomingServerPortNumberImap4(Integer
                                    .valueOf(IMAP_PORT_NUMBER_SECURE_OFF));
                            Log.d(TAG,
                                            providerDomain
                                                    + ": IncomingServerPortNumberImap4 = "
                                                    + portNumberImap4
                                                    + ", changeTo = "
                                                    + esp.getIncomingServerPortNumberImap4());
                        } else {
                            esp.setIncomingServerPortNumberImap4(Integer
                                    .valueOf(portNumberImap4));
                        }
                    }
                    if (protocol.equalsIgnoreCase("pop3") && esp != null) {
                        pop3Address = getXmlAttribute(mContext, xml, "address");
                        if (false == isXmlAttributeNullOrEmpty(pop3Address)) {
                            esp.setIncomingServerAddressPop3(pop3Address);
                        }
                        esp.setIncomingProtocolType(EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_POP3);

                        // If POP3 port number is empty, then set default value.
                        String portNumberPop3 = getXmlAttribute(mContext, xml,
                                "port");
                        if (TextUtils.isEmpty(portNumberPop3)) {
                            esp.setIncomingServerPortNumberPop3(Integer
                                    .valueOf(POP_PORT_NUMBER_SECURE_OFF));
                            Log.d(TAG,
                                            providerDomain
                                                    + ": IncomingServerPortNumberPop3 = "
                                                    + portNumberPop3
                                                    + ", changeTo = "
                                                    + esp.getIncomingServerPortNumberPop3());
                        } else {
                            esp.setIncomingServerPortNumberPop3(Integer
                                    .valueOf(portNumberPop3));
                        }
                    }

                    // [2014.09.22] add eas flow donghoe.kim - start
                    if (protocol.equalsIgnoreCase("eas")) {
                        easAddress = getXmlAttribute(mContext, xml, "address");
                        if (false == isXmlAttributeNullOrEmpty(easAddress)) {
                            esp.setIncomingServerAddress(easAddress);
                        }
                        esp.setIncomingProtocolType(EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_EAS);

                        String portNumberEAS = getXmlAttribute(mContext, xml,
                                "port");
                        if (TextUtils.isEmpty(portNumberEAS)) {
                            esp.setIncomingServerPortNumber(Integer
                                    .valueOf(EAS_PORT_NUMBER_SECURE_OFF));
                            Log.d(TAG, providerDomain
                                            + ": IncomingServerPortNumber = "
                                            + portNumberEAS + ", changeTo = "
                                            + esp.getIncomingServerPortNumber());
                        } else {
                            esp.setIncomingServerPortNumber(Integer
                                    .valueOf(portNumberEAS));
                        }
                    }
                    // [2014.09.22] add eas flow donghoe.kim - end

                    incomingSecurity = Short.valueOf(getXmlAttribute(mContext,
                            xml, "security"));
                    // LGE_CHANGE_PROTOCOL_BEGIN minwoo.hong 2014-5-8 backward
                    // compatibility
                    // TODO EAS Security type �솗�씤
                    /*
                    esp.setNeedSecureConnectionForIncoming(EEMAIL_SECURE_CONNECTION_TYPE
                            .convertToEnum(incomingSecurity));
                    */
                    esp.setSecurityForIncoming(incomingSecurity);
                    // LGE_CHANGE_PROTOCOL_END minwoo.hong 2014-5-8 backward
                    // compatibility
                    if (esp != null) {
                        esp.incomingUsername = xml.getAttributeValue(null,
                                "username");
                        esp.incomingPassword = xml.getAttributeValue(null,
                                "password");
                    }
                } else if (tag.equals("outgoing") && esp != null) {

                    smtpAddress = getXmlAttribute(mContext, xml, "address");
                    if (false == isXmlAttributeNullOrEmpty(smtpAddress)) {
                        esp.setOutgoingServerAddress(smtpAddress);
                    }
                    // If SMTP port number is empty, then set default value.
                    String portNumberSmtp = getXmlAttribute(mContext, xml,
                            "port");
                    if (TextUtils.isEmpty(portNumberSmtp)) {
                        esp.setOutgoingServerPortNumber(Integer
                                .valueOf(SMTP_PORT_NUMBER_SECURE_OFF));
                        Log.d(TAG,
                                providerDomain
                                        + ": OutgoingServerPortNumber = "
                                        + portNumberSmtp + ", changeTo = "
                                        + esp.getOutgoingServerPortNumber());
                    } else {
                        esp.setOutgoingServerPortNumber(Integer
                                .valueOf(portNumberSmtp));
                    }

                    String outgoingSecure = getXmlAttribute(mContext, xml,
                            "security");
                    if (!TextUtils.isEmpty(outgoingSecure)) {
                        outcomingSecurity = Short.valueOf(outgoingSecure);
                        esp.setSecurityForOutgoing(outcomingSecurity);
                        /*
                        esp.setNeedSecureConnectionForOutgoing(EEMAIL_SECURE_CONNECTION_TYPE
                                .convertToEnum(outcomingSecurity));
                        */
                    }
                    esp.smtpAuth = xml.getAttributeBooleanValue(null, "auth",
                            true);

                    if (esp.smtpAuth) {
                        esp.setAuthenticationType(EEMAIL_AUTHENTICATION_TYPE
                                .swigToEnum(1).swigValue());
                    } else {
                        esp.setAuthenticationType(EEMAIL_AUTHENTICATION_TYPE
                                .swigToEnum(0).swigValue());
                    }
                    if (esp != null) {
                        esp.outgoingUsername = xml.getAttributeValue(null,
                                "username");
                        esp.outgoingPassword = xml.getAttributeValue(null,
                                "password");
                    }
                    emailServiceProviders.add(esp);
                }
                break;
            default:
                break;
            }
            xmlEventType = xml.next();
        }
    }

}
