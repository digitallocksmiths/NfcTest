package com.digitallocksmiths.ItsoHce;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class VcardCmd2 extends VCard {

    // Constructor
    public VcardCmd2() {
        super();
    }


    public static VCard Factory(String szFilename) {
        return new VcardCmd2();
    };


    public String CreateImage() {
        return "VcardCmd2";
    }


}
