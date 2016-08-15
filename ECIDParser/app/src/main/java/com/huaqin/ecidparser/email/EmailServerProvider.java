package com.huaqin.ecidparser.email;

/**
 * Created by shiguibiao on 16-8-15.
 */

public class EmailServerProvider {
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
    public String outgoingSecurity;
    public String outgoingPort;
    public String outgoingUsername;
    public String outgoingPassword;
    public String smtpAuth;

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
        this.outgoingPort = null;
        this.outgoingUsername = null;
        this.outgoingPassword = null;
        this.smtpAuth = null;
        this.incomingSecurity = null;
    }
    public String getAddress() {
        return address;
    }

    public String getDomain() {
        return domain;
    }

    public String getName() {
        return name;
    }


    public String getIncomingAddress() {
        return incomingAddress;
    }

    public String getIncomingProtocol() {
        return incomingProtocol;
    }

    public String getIncomingSecurity() {
        return incomingSecurity;
    }

    public String getIncomingPort() {
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

    public String getOutgoingSecurity() {
        return outgoingSecurity;
    }

    public String getOutgoingPort() {
        return outgoingPort;
    }

    public String getOutgoingUsername() {
        return outgoingUsername;
    }

    public String getOutgoingPassword() {
        return outgoingPassword;
    }

    public String isSmtpAuth() {
        return smtpAuth;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setIncomingAddress(String incomingAddress) {
        this.incomingAddress = incomingAddress;
    }

    public void setIncomingProtocol(String incomingProtocol) {
        this.incomingProtocol = incomingProtocol;
    }

    public void setIncomingSecurity(String incomingSecurity) {
        this.incomingSecurity = incomingSecurity;
    }

    public void setIncomingPort(String incomingPort) {
        this.incomingPort = incomingPort;
    }

    public void setIncomingUsername(String incomingUsername) {
        this.incomingUsername = incomingUsername;
    }

    public void setIncomingPassword(String incomingPassword) {
        this.incomingPassword = incomingPassword;
    }

    public void setOutgoingAddress(String outgoingAddress) {
        this.outgoingAddress = outgoingAddress;
    }

    public void setOutgoingSecurity(String outgoingSecurity) {
        this.outgoingSecurity = outgoingSecurity;
    }

    public void setOutgoingPort(String outgoingPort) {
        this.outgoingPort = outgoingPort;
    }

    public void setOutgoingUsername(String outgoingUsername) {
        this.outgoingUsername = outgoingUsername;
    }

    public void setOutgoingPassword(String outgoingPassword) {
        this.outgoingPassword = outgoingPassword;
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
                +" outgoingSecurity:"+outgoingSecurity
                +" outgoingPort:"+outgoingPort
                +" outgoingUsername:"+outgoingUsername
                +" outgoingPassword:"+outgoingPassword
                +" smtpAuth:"+smtpAuth;
    }
}
