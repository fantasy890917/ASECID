package com.huaqin.ecidparser.email;

import android.util.Log;

import java.lang.reflect.Field;
import java.util.ArrayList;

public class OperatorConfigData {

    private Setting mSetting;
    private PreAccount mPreAccount;
    private WelcomeMessage mWelcomeMessage;
    private ArrayList<EmailServiceProvider> mEmailServiceProviders;

    public OperatorConfigData() {
        mSetting = new Setting();
        mPreAccount = new PreAccount();
        mWelcomeMessage = new WelcomeMessage();
        mEmailServiceProviders = new ArrayList<EmailServiceProvider>();
    }

    public synchronized Setting getSetting() {
        return mSetting;
    }

    public synchronized PreAccount getPreAccount() {
        return mPreAccount;
    }

    public synchronized WelcomeMessage getWelcomeMessage() {
        return mWelcomeMessage;
    }

    public synchronized ArrayList<EmailServiceProvider> getEmailServiceProvider() {
        return mEmailServiceProviders;
    }

    public class Setting {

        /* General Settings */
        public boolean syncRoaming; // using value - General settings :
                                       // Roaming
        public boolean syncRoming; // using value - General settings :
                                      // Roaming -> will be removed..

        /* Account settings Common */
        public boolean signatureEnable; // using value - Account settings :
                                           // Signature (Common)
        public String signature; // using value - Account settings :
                                    // Signature (Common)

        /* Accout settings Imap/Pop */
        public int syncInterval; // using value - Account settings : Retrieve
                                    // interval (Imap, Pop) - setup wizard
        public int popDeletePolicy; // delete from server (pop3) - not used
        public int maxEmailtoShow; // using value - Account settings :
                                      // Maximum emails to show (Imap, Pop) -
                                      // setup wizard

        /* Accout settings EAS */
        public int updateScheduleInPeak;
        public int updateScheduleOffPeak;
        public int emailDaystoSync; // using value - Account settings : Days
                                       // to sync email (EAS) - setup wizard
        public int messageSizeLimit;
        public boolean contactSync;
        public boolean calendarSync;
        public boolean tasksSync;
        public int calendarSyncAmount; // not used
        // LGE_CHANGE_SMS_SYNC_BEGIN bill23.kim
        public boolean smsSync; // not support operator_default xml
        // LGE_CHANGE_SMS_SYNC_END bill23.kim
        // LGE_CHANGE_NOTE_SYNC_BEGIN sunghwa.woo
        public boolean noteSync;
        // LGE_CHANGE_NOTE_SYNC_END sunghwa.woo

        /* not used.. */
        public boolean espEnable;
        public boolean smtpAuth;
        public int espMode;
        public int easSyncAmount;
        public boolean notifyEnable;
        public int notifyVibrate;
        public boolean changeProtocolEnable;
        public String imapOperatorId;
        public boolean easProxy;

        public Setting() {
//            defaultSettingsValue();
//            notifyEnable = GlobalEnvironment.getApplicationContext().getResources()
//                    .getBoolean(R.bool.default_setting_use_notification);
            
            //< 2016/01/21-V5162-Yuting.Feng, [D3][BUG][COMMON][EMAIL][MEXTEL][TD6539] Email nofitication inquiry.
            //notifyEnable = false;
			notifyEnable = true; 
            //>2016/01/21-V5162-Yuting.Feng
//            GlobalEnvironment.getApplicationContext().getResources()
//                    .getBoolean(R.bool.default_setting_use_notification);
//            
            
            notifyVibrate = -1;

            /* not used.. */
            espEnable = true;
            smtpAuth = true;
            espMode = 0;
//            easSyncAmount = SyncWindow.SYNC_WINDOW_3_DAYS;
            easSyncAmount = -1;
            changeProtocolEnable = true;
            imapOperatorId = "";
            easProxy = false;
        }

        @Deprecated
        public boolean isEspEnable() {
            return espEnable;
        }

        @Deprecated
        public int getEspMode() {
            return espMode;
        }

        @Deprecated
        public int getEasSyncAmount() {
            return easSyncAmount;
        }

        public boolean isSyncRoaming() {
            return syncRoaming && syncRoming;
        }

        public int getSyncInterval() {
            return syncInterval;
        }

        public int getPopDeletePolicy() {
            return popDeletePolicy;
        }

        public boolean isSmtpAuth() {
            return smtpAuth;
        }


        public boolean isSignatureEnable() {
            return signatureEnable;
        }

        public String getSignature() {
            return signature;
        }

       public boolean isNotifyEnable()
        {
            return notifyEnable;
        }
        public boolean isCalendarSync()
        {
            return calendarSync;
        }
        public boolean isContactSync()
        {
            return contactSync ;
        }

        public int getCalendarSyncAmount() {
            return calendarSyncAmount;
        }

        public boolean isChangeProtocolEnable() {
            return changeProtocolEnable;
        }

        public String getImapOperatorId() {
            return imapOperatorId;
        }

        public boolean isEasProxy() {
            return easProxy;
        }

        /* rabbani.shaik@lge.com ,11, July 2012,AccountSettings -- [Start] */
        public boolean isTasksSync() {
            return tasksSync;
        }

        public int getMaxEmailtoShow() {
            return maxEmailtoShow;
        }

        public int getMessageSizeLimit() {
            return messageSizeLimit;
        }

        // LGE_CHANGE_SMS_SYNC_BEGIN bill23.kim
        public boolean isSmsSync() {
            return smsSync;
        }

        // LGE_CHANGE_SMS_SYNC_END bill23.kim

        // LGE_CHANGE_NOTE_SYNC_BEGIN sunghwa.woo
        public boolean isNoteSync() {
            return noteSync;
        }

        // LGE_CHANGE_NOTE_SYNC_END sunghwa.woo
    }

    public class PreAccount {

        public String address;
        public String domain;
        public String name;
        public String desc;
        public String incomingAddress;
        public String incomingProtocol;
        public int incomingSecurity;
        public int incomingPort;
        public String incomingUsername;
        public String incomingPassword;
        public String outgoingAddress;
        public int outgoingSecurity;
        public int outgoingPort;
        public String outgoingUsername;
        public String outgoingPassword;
        public boolean smtpAuth;

        public String getAddress() {
            return address;
        }

        public String getDomain() {
            return domain;
        }

        public String getName() {
            return name;
        }

        public String getDesc() {
            return desc;
        }

        public String getIncomingAddress() {
            return incomingAddress;
        }

        public String getIncomingProtocol() {
            return incomingProtocol;
        }

        public int getIncomingSecurity() {
            return incomingSecurity;
        }

        public int getIncomingPort() {
            return incomingPort;
        }

        public String getIncomingUsername() {
            return incomingUsername;
        }

        public String getIncomingPassword() {
            return incomingPassword;
        }

        public String getOutgoingAddress() {
            return outgoingAddress;
        }

        public int getOutgoingSecurity() {
            return outgoingSecurity;
        }

        public int getOutgoingPort() {
            return outgoingPort;
        }

        public String getOutgoingUsername() {
            return outgoingUsername;
        }

        public String getOutgoingPassword() {
            return outgoingPassword;
        }

        public boolean isSmtpAuth() {
            return smtpAuth;
        }
    }

    public class WelcomeMessage {
        public String from;
        public String name;
        public String subject;
        public String body;

        public String getFrom() {
            return from;
        }

        public String getName() {
            return name;
        }

        public String getSubject() {
            return subject;
        }

        public String getBody() {
            return body;
        }
    }

    public class Espdata {
        public String m_sDescription;
        public String m_sDomain;

        public String m_sSupportedProtocalType;

        public EEMAIL_PROTOCOL_TYPE m_eIncomingProtocolType;

        public String m_szIncomingServerAddress;
        public int m_nIncomingServerPortNumber;

        public String m_szIncomingServerAddressImap4;
        public int m_nIncomingServerPortNumberImap4;

        public String m_szIncomingServerAddressPop3;
        public int m_nIncomingServerPortNumberPop3;

        public String m_szOutgoingServerAddress;
        public int m_nOutgoingServerPortNumber;

        public EEMAIL_SECURE_CONNECTION_TYPE m_bNeedSecureConnectionForIncoming;
        public EEMAIL_SECURE_CONNECTION_TYPE m_bNeedSecureConnectionForOutgoing;

        public int m_bUseFullAddressId;
        public int m_bUseLogo;
        public String m_sLogoUri;

        public String m_sDefaultUserId;
        public String m_sDefaultUserPassword;
        public String m_sDefaultEmailAddress;
        // private EEMAIL_AUTHENTICATION_TYPE m_eAuthenticationType =
        // EEMAIL_AUTHENTICATION_TYPE.eEMAIL_AUTHENTICATION_TYPE_SMTP_AUTH;
        // AuthenticationType is Bit Flag EEMAIL_AUTHENTICATION_TYPE -> int
        public int m_nAuthenticationType = 1;

        public Espdata() {
            m_eIncomingProtocolType = EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_POP3;
            m_sSupportedProtocalType = "both";
        }

        public Espdata(EmailServiceProvider provider) {
            this.m_sDescription = provider.getDescription();
            this.m_sDomain = provider.getDomain();
            this.m_sSupportedProtocalType = provider.getSupportedProtocalType();
            this.m_eIncomingProtocolType = provider.getIncomingProtocolType();
            this.m_szIncomingServerAddress = provider
                    .getIncomingServerAddress();
            this.m_szIncomingServerAddressImap4 = provider
                    .getIncomingServerAddressImap4();
            this.m_nIncomingServerPortNumberImap4 = provider
                    .getIncomingServerPortNumberImap4();
            this.m_szIncomingServerAddressPop3 = provider
                    .getIncomingServerAddressPop3();
            this.m_nIncomingServerPortNumberPop3 = provider
                    .getIncomingServerPortNumberPop3();
            this.m_szOutgoingServerAddress = provider
                    .getOutgoingServerAddress();
            this.m_nOutgoingServerPortNumber = provider
                    .getOutgoingServerPortNumber();

            this.m_bNeedSecureConnectionForIncoming = provider
                    .getNeedSecureConnectionForIncoming();
            this.m_bNeedSecureConnectionForOutgoing = provider
                    .getNeedSecureConnectionForOutgoing();
            this.m_bUseFullAddressId = provider.getUseFullAddressId();
            this.m_bUseLogo = provider.getUseLogo();

            this.m_sDefaultUserId = provider.getDefaultUserId();
            this.m_sDefaultUserPassword = provider.getDefaultUserPassword();
            this.m_sDefaultEmailAddress = provider.getDefaultEmailAddress();
            this.m_nAuthenticationType = provider.getAuthenticationType();
        }

    }

    public  class EmailServiceProvider extends MailServerProvider {

        private static final long serialVersionUID = -632734474746006725L;

        public String emailAddress;
        public String incomingPassword;
        public String outgoingPassword;
        public boolean smtpAuth;
        public String incomingUsername;
        public String outgoingUsername;

        public String getEmailAddress() {
            return emailAddress;
        }

        public String getIncomingPassword() {
            return incomingPassword;
        }

        public String getOutgoingPassword() {
            return outgoingPassword;
        }

        public boolean isSmtpAuth() {
            return smtpAuth;
        }

        public String getIncomingUsername() {
            return incomingUsername;
        }

        public String getOutgoingUsername() {
            return outgoingUsername;
        }
    }

    @Override
    public String toString() {
        StringBuffer sb = new StringBuffer();
        // Field[] items = null;
        // basanta.behera@lge.com,18, July 2012, Start
        // setSetting(sb, items);
        // setWelcomemsg(sb, items);
        // setPreAccount(sb, items);
        // setEas(sb, items);
        // basanta.behera@lge.com,18, July 2012, End
        // START WBT #2 donghoe.kim@lge.com
        // setSetting(sb);
        // setWelcomemsg(sb);
        // setPreAccount(sb);
        setProfileInfo(sb, mSetting);
        setProfileInfo(sb, mWelcomeMessage);
        setProfileInfo(sb, mPreAccount);
        setEas(sb);
        // END WBT #2 donghoe.kim@lge.com
        if (sb == null) {
            return null;
        }
        return sb.toString();
    }

    // private void setWelcomemsg(StringBuffer sb, Field[] items) {
    private void setProfileInfo(StringBuffer sb, Object obj) {
        String appendStartMsg = "";
        String appendEndMsg = "";
        // String appendNullMsg = "";
        if (mSetting.equals(obj)) {
            appendStartMsg = "== Setting START ==";
            appendEndMsg = "== Setting END ==";
            // appendNullMsg = "setting is null";
        } else if (mWelcomeMessage.equals(obj)) {
            appendStartMsg = "== Welcome msg START ==";
            appendEndMsg = "== Welcome Message END ==";
            // appendNullMsg = "welcome msg is null";
        } else if (mPreAccount.equals(obj)) {
            appendStartMsg = "== Pre Account START ==";
            appendEndMsg = "== Pre Account END ==";
            // appendNullMsg = "Pre-account is null";
        } else {
            return;
        }

        sb.append("\n").append(appendStartMsg).append("\n");

        if (obj != null) {
            Field[] items = obj.getClass().getDeclaredFields();
            for (Field item : items) {
                item.setAccessible(true);
                try {
                    if (!(item.get(obj) instanceof OperatorConfigData)) {
                        sb.append(item.getName()).append(" : ")
                                .append(item.get(obj)).append("\n");
                    }
                } catch (IllegalAccessException e) {
                    Log.e(getClass().getName(),
                             " : error get class info");
                }
            }
        }
        // else {
        // sb.append(appendNullMsg).append("\n");
        // }
        sb.append(appendEndMsg).append("\n");
    }

    private void setEas(StringBuffer sb) {
        sb.append("== ESP START ==").append("\n");
        if (mEmailServiceProviders != null) {
            int inx = 0;
            for (EmailServiceProvider esp : mEmailServiceProviders) {
                Espdata espdata = new Espdata(esp);
                sb.append("- ESP " + ++inx + " -").append("\n");
                for (Field item : espdata.getClass().getFields()) {
                    try {
                        sb.append(item.getName()).append(" : ")
                                .append(item.get(espdata)).append("\n");
                    } catch (IllegalAccessException e) {
                        Log.d(getClass().getName() ,
                               " : error get class info");
                    }
                }
                Field[] items = esp.getClass().getDeclaredFields();
                for (Field item : items) {
                    item.setAccessible(true);
                    try {
                        if (!(item.get(esp) instanceof OperatorConfigData)) {
                            sb.append(item.getName()).append(" : ")
                                    .append(item.get(esp)).append("\n");
                        }
                    } catch (IllegalAccessException e) {
                        Log.e(getClass().getName(),
                                " : error get class info");
                    }
                }
            }
        } else {
            sb.append("emailserviceprovider is null").append("\n");
        }
        sb.append("== ESP END ==").append("\n");

    }
    // basanta.behera@lge.com,18, July 2012, End

}
