package com.huaqin.ecidparser.email;

import java.io.Serializable;

public class MailServerProvider implements Serializable {
    private static final long serialVersionUID = 1L;
    private String m_sDescription;
    private String m_sDomain;

    private String m_sSupportedProtocalType;

    private EEMAIL_PROTOCOL_TYPE m_eIncomingProtocolType;

    private String m_szIncomingServerAddress;
    private int m_nIncomingServerPortNumber;

    private String m_szIncomingServerAddressImap4;
    private int m_nIncomingServerPortNumberImap4;

    private String m_szIncomingServerAddressPop3;
    private int m_nIncomingServerPortNumberPop3;

    private String m_szOutgoingServerAddress;
    private int m_nOutgoingServerPortNumber;

    private EEMAIL_SECURE_CONNECTION_TYPE m_bNeedSecureConnectionForIncoming;
    private EEMAIL_SECURE_CONNECTION_TYPE m_bNeedSecureConnectionForOutgoing;

    private short m_securityForIncoming;
    private short m_securityForOutgoing;

    private int m_bUseFullAddressId;
    private int m_bUseLogo;
    private String m_sLogoUri;

    private String m_sDefaultUserId;
    private String m_sDefaultUserPassword;
    private String m_sDefaultEmailAddress;
    //private EEMAIL_AUTHENTICATION_TYPE	m_eAuthenticationType	= EEMAIL_AUTHENTICATION_TYPE.eEMAIL_AUTHENTICATION_TYPE_SMTP_AUTH;
    // AuthenticationType is Bit Flag EEMAIL_AUTHENTICATION_TYPE -> int
    private int m_nAuthenticationType = EEMAIL_AUTHENTICATION_TYPE.eEMAIL_AUTHENTICATION_TYPE_NO_AUTH
            .swigValue();

    public MailServerProvider() {
        m_eIncomingProtocolType = EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_UNKNOWN;
        m_sSupportedProtocalType = "both";
    }

    public MailServerProvider(String discription) {
        //[2011.07.25][wooky][VZW:2314] WBT 180109  
        //discription.replace(" / Msn", ""); //[2011.06.29][KKYUN][VZW:2092] 援ъ“媛쒖꽑 �빐�빞�븯吏�留� AccountNewMain 踰꾨┫ �삁�젙�씠湲� �븣臾몄뿉 �떖�떆 泥섎━濡� �벐�젅湲� 肄붾뱶
        m_sDescription = discription;
        m_bUseLogo = 1;
        m_eIncomingProtocolType = EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_UNKNOWN;
        m_sSupportedProtocalType = "both";
    }

    public MailServerProvider(MailServerProvider provider) {
        this.m_sDescription = provider.m_sDescription;
        this.m_sDomain = provider.m_sDomain;
        this.m_sSupportedProtocalType = provider.m_sSupportedProtocalType;
        this.m_eIncomingProtocolType = provider.m_eIncomingProtocolType;
        this.m_szIncomingServerAddress = provider.m_szIncomingServerAddress;
        this.m_szIncomingServerAddressImap4 = provider.m_szIncomingServerAddressImap4;
        this.m_nIncomingServerPortNumberImap4 = provider.m_nIncomingServerPortNumberImap4;
        this.m_szIncomingServerAddressPop3 = provider.m_szIncomingServerAddressPop3;
        this.m_nIncomingServerPortNumberPop3 = provider.m_nIncomingServerPortNumberPop3;
        this.m_szOutgoingServerAddress = provider.m_szOutgoingServerAddress;
        this.m_nOutgoingServerPortNumber = provider.m_nOutgoingServerPortNumber;

        this.m_bNeedSecureConnectionForIncoming = provider.m_bNeedSecureConnectionForIncoming;
        this.m_bNeedSecureConnectionForOutgoing = provider.m_bNeedSecureConnectionForOutgoing;
        this.m_bUseFullAddressId = provider.m_bUseFullAddressId;
        this.m_bUseLogo = provider.m_bUseLogo;

        this.m_sDefaultUserId = provider.m_sDefaultUserId;
        this.m_sDefaultUserPassword = provider.m_sDefaultUserPassword;
        this.m_sDefaultEmailAddress = provider.m_sDefaultEmailAddress;
        this.m_nAuthenticationType = provider.m_nAuthenticationType;
    }

    public String getDefaultEmailAddress() {
        return m_sDefaultEmailAddress;
    }

    public void setDefaultEmailAddress(String defaultEmailAddress) {
        m_sDefaultEmailAddress = defaultEmailAddress;
    }

    public String getDefaultUserId() {
        return m_sDefaultUserId;
    }

    public void setDefaultUserId(String defaultUserId) {
        m_sDefaultUserId = defaultUserId;
    }

    public String getDefaultUserPassword() {
        return m_sDefaultUserPassword;
    }

    public void setDefaultUserPassword(String defaultUserPassword) {
        m_sDefaultUserPassword = defaultUserPassword;
    }

    public int getAuthenticationType() {
        return m_nAuthenticationType;
    }

    public void setAuthenticationType(int authenticationType) {
        m_nAuthenticationType = authenticationType;
    }

    public String getSupportedProtocalType() {
        return m_sSupportedProtocalType;
    }

    public void setSupportedProtocalType(String supportedProtocalType) {
        m_sSupportedProtocalType = supportedProtocalType;
    }

    public String getDescription() {
        return m_sDescription;
    }

    public void setDescription(String description) {
        //[2011.07.25][wooky][VZW:2314] WBT 180109
        //description = description = description.replace(" / Msn", ""); //[2011.06.29][KKYUN][VZW:2092] 援ъ“媛쒖꽑 �빐�빞�븯吏�留� AccountNewMain 踰꾨┫ �삁�젙�씠湲� �븣臾몄뿉 �떖�떆 泥섎━濡� �벐�젅湲� 肄붾뱶
        m_sDescription = description;
    }

    public int getUseLogo() {
        return m_bUseLogo;
    }

    public void setUseLogo(int useLogo) {
        m_bUseLogo = useLogo;
    }

    public int getUseFullAddressId() {
        return m_bUseFullAddressId;
    }

    public void setUseFullAddressId(int useFullAddressId) {
        m_bUseFullAddressId = useFullAddressId;
    }

    public EEMAIL_SECURE_CONNECTION_TYPE getNeedSecureConnectionForIncoming() {
        return m_bNeedSecureConnectionForIncoming;
    }

    public void setNeedSecureConnectionForIncoming(
            EEMAIL_SECURE_CONNECTION_TYPE needSecureConnectionForIncoming) {
        m_bNeedSecureConnectionForIncoming = needSecureConnectionForIncoming;
    }

    public EEMAIL_SECURE_CONNECTION_TYPE getNeedSecureConnectionForOutgoing() {
        return m_bNeedSecureConnectionForOutgoing;
    }

    public void setNeedSecureConnectionForOutgoing(
            EEMAIL_SECURE_CONNECTION_TYPE needSecureConnectionForOutgoing) {
        m_bNeedSecureConnectionForOutgoing = needSecureConnectionForOutgoing;
    }

    public short getSecurityForIncoming() {
        return m_securityForIncoming;
    }

    public void setSecurityForIncoming(
            short securityForIncoming) {
        m_securityForIncoming = securityForIncoming;
    }

    public short getSecurityForOutgoing() {
        return m_securityForOutgoing;
    }

    public void setSecurityForOutgoing(
            short securityForOutgoing) {
        m_securityForOutgoing = securityForOutgoing;
    }

    public String getDomain() {
        return m_sDomain;
    }

    public void setDomain(String domain) {
        m_sDomain = domain;
    }

    public void setIncomingProtocolType(EEMAIL_PROTOCOL_TYPE m_eIncomingProtocolType) {
        this.m_eIncomingProtocolType = m_eIncomingProtocolType;
    }

    public EEMAIL_PROTOCOL_TYPE getIncomingProtocolType() {
        return m_eIncomingProtocolType;
    }

    public String getIncomingServerAddress() {
        if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_POP3) {
            return m_szIncomingServerAddressPop3;
        } else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_IMAP4) {
            return m_szIncomingServerAddressImap4;
        }
        //[2014.09.22] add eas flow donghoe.kim - start
        else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_EAS) {
            return m_szIncomingServerAddress;
        }
        //[2014.09.22] add eas flow donghoe.kim - end
        return m_szIncomingServerAddress;
    }

    public void setIncomingServerAddress(String incomingServerAddress) {
        if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_POP3) {
            m_szIncomingServerAddressPop3 = incomingServerAddress;
        } else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_IMAP4) {
            m_szIncomingServerAddressImap4 = incomingServerAddress;
        }
        //[2014.09.22] add eas flow donghoe.kim - start
        else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_EAS) {
            m_szIncomingServerAddress = incomingServerAddress;
        }
        //[2014.09.22] add eas flow donghoe.kim - end
        m_szIncomingServerAddress = incomingServerAddress;
    }

    public int getIncomingServerPortNumber() {
        if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_POP3) {
            return m_nIncomingServerPortNumberPop3;
        } else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_IMAP4) {
            return m_nIncomingServerPortNumberImap4;
        }
        //[2014.09.22] add eas flow donghoe.kim - start
        else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_EAS) {
            return m_nIncomingServerPortNumber;
        }
        //[2014.09.22] add eas flow donghoe.kim - end
        return m_nIncomingServerPortNumber;
    }

    public void setIncomingServerPortNumber(int incomingServerPortNumber) {
        if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_POP3) {
            m_nIncomingServerPortNumberPop3 = incomingServerPortNumber;
        } else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_IMAP4) {
            m_nIncomingServerPortNumberImap4 = incomingServerPortNumber;
        }
        //[2014.09.22] add eas flow donghoe.kim - start
        else if (m_eIncomingProtocolType == EEMAIL_PROTOCOL_TYPE.eEMAIL_PROTOCOL_TYPE_EAS) {
            m_nIncomingServerPortNumber = incomingServerPortNumber;
        }
        //[2014.09.22] add eas flow donghoe.kim - end
        m_nIncomingServerPortNumber = incomingServerPortNumber;
    }

    public String getOutgoingServerAddress() {
        return m_szOutgoingServerAddress;
    }

    public void setOutgoingServerAddress(String outgoingServerAddress) {
        m_szOutgoingServerAddress = outgoingServerAddress;
    }

    public int getOutgoingServerPortNumber() {
        return m_nOutgoingServerPortNumber;
    }

    public void setOutgoingServerPortNumber(int outgoingServerPortNumber) {
        m_nOutgoingServerPortNumber = outgoingServerPortNumber;
    }

    public String getIncomingServerAddressImap4() {
        return m_szIncomingServerAddressImap4;
    }

    public void setIncomingServerAddressImap4(String incomingServerAddressImap4) {
        m_szIncomingServerAddressImap4 = incomingServerAddressImap4;
    }

    public int getIncomingServerPortNumberImap4() {
        return m_nIncomingServerPortNumberImap4;
    }

    public void setIncomingServerPortNumberImap4(int incomingServerPortNumberImap4) {
        m_nIncomingServerPortNumberImap4 = incomingServerPortNumberImap4;
    }

    public String getIncomingServerAddressPop3() {
        return m_szIncomingServerAddressPop3;
    }

    public void setIncomingServerAddressPop3(String incomingServerAddressPop3) {
        m_szIncomingServerAddressPop3 = incomingServerAddressPop3;
        m_szIncomingServerAddress = incomingServerAddressPop3;
    }

    public int getIncomingServerPortNumberPop3() {
        return m_nIncomingServerPortNumberPop3;
    }

    public void setIncomingServerPortNumberPop3(int incomingServerPortNumberPop3) {
        m_nIncomingServerPortNumberPop3 = incomingServerPortNumberPop3;
        m_nIncomingServerPortNumber = incomingServerPortNumberPop3;
    }

    public String convertSecurityForm(short security) {
        if (security == 1) {
            return "SSL";
        } else if (security == 2) {
            return "STARTTLS";
        } else if (security == 3) {
            return "TLS";
        } else {
            return "OFF";
        } 
    }
    public String convertOnOffForm(int number) {
        if (number == 1) {
            return "On";
        } else {
            return "Off";
        } 
    }

}
