package com.huaqin.ecidparser.contacts;

/**
 * Created by shiguibiao on 16-8-13.
 */

public interface ContactsParserAttribute {

    public static final String ATTR_ITEM_STORAGE = "NEW_CONTACT_DEFAULT";

    /**
     * add new contacts default storage in phone memory
     */
    public static final int IN_PHONE_MEMORY = 0;

    /**
     * add new contacts default storage in sim memory
     */
    public static final int IN_SIM_MEMORY = 1;

    /**
     * add new contacts default storage in sim memory
     */
    public static final String ATTR_VALUE_SIM_STORAGE = "In SIM memory";

    /**
     * add new contacts default storage in phone memory
     */
    public static final String ATTR_VALUE_PHONE_STORAGE = "In Phone Memory";


    public static final String  KEY_DEFAULT_STORAGE_LOCATION = "Phonebook@Default_Storage_Location";
}
