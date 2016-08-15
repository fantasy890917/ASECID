package com.huaqin.ecidparser.email;

/**
 * Created by shiguibiao on 16-8-15.
 */

public class EmailSettingsInfo {

    public String notification;
    public String signature;
    public String espMode;
    public String contactSync;
    public String calendarSync;
    public String tasksSync;
    public String smsSync;
    public EmailSettingsInfo(){
        this.notification = null;
        this.signature = null;
        this.espMode = null;
        this.contactSync = null;
        this.calendarSync = null;
        this.tasksSync = null;
        this.smsSync = null;
    }
    public void setNotification(String notification) {
        this.notification = notification;
    }

    public void setSmsSync(String smsSync) {
        this.smsSync = smsSync;
    }

    public void setTasksSync(String tasksSync) {
        this.tasksSync = tasksSync;
    }

    public void setCalendarSync(String calendarSync) {
        this.calendarSync = calendarSync;
    }

    public void setContactSync(String contactSync) {
        this.contactSync = contactSync;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public void setEspMode(String espMode) {
        this.espMode = espMode;
    }

    public String getNotification() {
        return notification;
    }

    public String getSignature() {
        return signature;
    }

    public String getEspMode() {
        return espMode;
    }

    public String getContactSync() {
        return contactSync;
    }

    public String getCalendarSync() {
        return calendarSync;
    }

    public String getTasksSync() {
        return tasksSync;
    }

    public String getSmsSync() {
        return smsSync;
    }
}
