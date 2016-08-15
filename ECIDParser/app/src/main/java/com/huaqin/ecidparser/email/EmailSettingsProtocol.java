package com.huaqin.ecidparser.email;

/**
 * Created by shiguibiao on 16-8-15.
 */

public class EmailSettingsProtocol {

    public String syncRoaming;
    public String syncInterval;
    public String popDeletePolicy;
    public String easProxy;
    public String updateScheduleInPeak;
    public String updateScheduleOffPeak;

    public EmailSettingsProtocol(){
        this.syncRoaming =null;
        this.syncInterval =null;
        this.popDeletePolicy = null;
        this.easProxy = null;
        this.updateScheduleInPeak = null;
        this.updateScheduleOffPeak = null;
    }
    public void setUpdateScheduleOffPeak(String updateScheduleOffPeak) {
        this.updateScheduleOffPeak = updateScheduleOffPeak;
    }

    public void setUpdateScheduleInPeak(String updateScheduleInPeak) {
        this.updateScheduleInPeak = updateScheduleInPeak;
    }

    public void setEasProxy(String easProxy) {
        this.easProxy = easProxy;
    }

    public void setPopDeletePolicy(String popDeletePolicy) {
        this.popDeletePolicy = popDeletePolicy;
    }

    public void setSyncInterval(String syncInterval) {
        this.syncInterval = syncInterval;
    }

    public void setSyncRoaming(String syncRoaming) {
        this.syncRoaming = syncRoaming;
    }

    public String getPopDeletePolicy() {
        return popDeletePolicy;
    }

    public String getSyncRoaming() {
        return syncRoaming;
    }

    public String getSyncInterval() {
        return syncInterval;
    }

    public String getEasProxy() {
        return easProxy;
    }

    public String getUpdateScheduleInPeak() {
        return updateScheduleInPeak;
    }

    public String getUpdateScheduleOffPeak() {
        return updateScheduleOffPeak;
    }

    @Override
    public String toString(){
        return "EmailSettingsProtocol,syncRoaming:"+syncRoaming
                +" syncInterval:"+syncInterval
                +" popDeletePolicy:"+popDeletePolicy
                +" easProxy:"+easProxy
                +" updateScheduleInPeak:"+updateScheduleInPeak
                +" updateScheduleOffPeak:"+updateScheduleOffPeak;

    }
}
