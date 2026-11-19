package com.digitallocksmiths.ItsoHce;

import static java.lang.System.arraycopy;

import java.util.Arrays;

public class Apdu {



    public enum ApduCase {Malformed, One, Two, Three, Four, TwoE, ThreeE, FourE}

    public ApduCase apduCase;

    public int      Cla             = 0;
    public int      Ins             = 0;
    public int      P1              = 0;
    public int      P2              = 0;
    public int      Lc              = 0;        // data bytes received
    public int      Le              = 0;        // data bytes to be returned
    public boolean  fAsMuchAsWeHave = false;    // is Le literal/false or max/true
    public byte[]   baApdu;
    public byte[]   baRxData        = null;

    // =========================================================================================
    // Apdu constructor
    //
    public Apdu(byte[] baApdu) {
        this.baApdu = baApdu;                                                                   // Remember the APDU

        // Work out its case
        if ((baApdu == null) || (baApdu.length < 4)) {                                          // WTF = garbage
            apduCase = ApduCase.Malformed;                                                      //
        }
        else if (baApdu.length == 4) {                                                          //
            apduCase = ApduCase.One;                                                            // 1: Short form
            Lc = 0;                                                                             //      no RX
            Le = 0;                                                                             //      or TX
        }
        else if (baApdu.length == 5) {                                                          //
            apduCase = ApduCase.Two;                                                            // 2: Short form
            Lc = 0;                                                                             //      no RX
            Le = baApdu[4] & 0xFF;                                                              //      TX = 1..256 bytes expected
            if (Le == 0) {
                Le = 256;
                fAsMuchAsWeHave = true;
            }                                 //      0 ==> 256, as much as we have
        }
        else if (baApdu[4] != 0) {                                                              // not extended
            int iLen = baApdu[4] & 0xFF;                                                        //
            if (baApdu.length == (5 + iLen)) {                                                  //
                apduCase = ApduCase.Three;                                                      //      3: Short
                Lc = iLen;                                                                      //          RX = volume delivered
                Le = 0;                                                                         //          TX = no response expected
            }
            else if (baApdu.length == (5 + iLen + 1)) {                                         //
                apduCase = ApduCase.Four;                                                       //      4: Short form
                Lc = iLen;                                                                      //          RX = volume delivered
                Le = baApdu[baApdu.length - 1];                                                 //          TX = 1..256 bytes expected
                if (Le == 0) {
                    Le = 256;
                    fAsMuchAsWeHave = true;
                }                             //           0 ==> 256, as much as we have
            }
            else {                                                                              //      malformed
                apduCase = ApduCase.Malformed;                                                  //
            }                                                                                   //
        }
        else if (baApdu.length == 6) {                                                          // not short or extended
            apduCase = ApduCase.Malformed;                                                      //      malformed
        }
        else {                                                                                  // is extended, len >= 7 and [4] == 0
            int iLen = ((baApdu[5] & 0xFF) << 8) | (baApdu[6] & 0xff);
            if (baApdu.length == 7) {                                                           //
                apduCase = ApduCase.TwoE;                                                       //      2e: Extended form TX expected
                Lc = 0;                                                                         //          RX = 0
                Le = iLen;                                                                      //          TX = 0..65535
                if (Le == 0) {
                    Le = 0xffff;
                    fAsMuchAsWeHave = true;
                }                          //           0 ==> 65535, as much as we have
            }
            else {
                if (baApdu.length == 7 + iLen) {
                    apduCase = ApduCase.ThreeE;                                                 //      3e: Extended form RX here
                    Lc = iLen;                                                                  //          RX = volume delivered
                    Le = 0;                                                                     //          TX = no response expected
                }
                else if (baApdu.length == 7 + iLen + 2) {
                    apduCase = ApduCase.FourE;                                                  //      4e Extended form TX here and TX expected
                    Lc = iLen;                                                                  //          RX = volume delivered
                    Le = ((baApdu[7 + iLen] & 0xFF) << 8) | (baApdu[8 + iLen] & 0xff);          //          TX = 1..256 bytes expected
                    if (Le == 0) {
                        Le = 0xffff;
                        fAsMuchAsWeHave = true;
                    }                      //           0 ==> 65535, as much as we have
                }
                else {                                                                          // Anything else ...
                    apduCase = ApduCase.Malformed;                                              //      malformed
                }
            }
        }
        if (apduCase != ApduCase.Malformed) {                                                   //Now update the fields.
            Cla = (baApdu[0] & 0xFF);                                                           //
            Ins = (baApdu[1] & 0xFF);                                                           //
            P1  = (baApdu[2] & 0xFF);                                                           //
            P2  = (baApdu[3] & 0xFF);                                                           //
            if ((apduCase == ApduCase.Three || apduCase == ApduCase.Four)) {                    // Separate out Rx Data if we have any
                baRxData = Arrays.copyOfRange(baApdu, 5, 5 + Lc);                               //      short is from 5...
            }                                                                                   //
            else if ((apduCase == ApduCase.ThreeE || apduCase == ApduCase.FourE)) {             //
                baRxData = Arrays.copyOfRange(baApdu, 7, 7 + Lc);                               //      Extended is from 7...
            }
        } // constructor Apdu

    } //class Apdu


    public static class SW {                                                                        // Status words
        public static final short NO_ERROR                       = (short)0x9000;                   // No Error
        public static final short BYTES_REMAINING_00             = (short)0x6100;                   // Response bytes remaining
        public static final short WRONG_LENGTH                   = (short)0x6700;                   // Wrong length
        public static final short SECURITY_STATUS_NOT_SATISFIED  = (short)0x6982;                   // Security condition not satisfied
        public static final short FILE_INVALID                   = (short)0x6983;                   // File invalid
        public static final short DATA_INVALID                   = (short)0x6984;                   // Data invalid
        public static final short CONDITIONS_NOT_SATISFIED       = (short)0x6985;                   // Conditions of use not satisfied
        public static final short COMMAND_NOT_ALLOWED            = (short)0x6986;                   // Command not allowed (no current EF)
        public static final short APPLET_SELECT_FAILED           = (short)0x6999;                   // Applet selection failed
        public static final short WRONG_DATA                     = (short)0x6A80;                   // Wrong data
        public static final short FUNC_NOT_SUPPORTED             = (short)0x6A81;                   // Function not supported
        public static final short FILE_NOT_FOUND                 = (short)0x6A82;                   // File not found
        public static final short RECORD_NOT_FOUND               = (short)0x6A83;                   // Record not found
        public static final short INCORRECT_P1P2                 = (short)0x6A86;                   // Incorrect parameters (P1,P2)
        public static final short WRONG_P1P2                     = (short)0x6B00;                   // Incorrect parameters (P1,P2)
        public static final short CORRECT_LENGTH_00              = (short)0x6C00;                   // Correct Expected Length (Le)
        public static final short INS_NOT_SUPPORTED              = (short)0x6D00;                   // INS value not supported
        public static final short CLA_NOT_SUPPORTED              = (short)0x6E00;                   // CLA value not supported
        public static final short UNKNOWN                        = (short)0x6F00;                   // No precise diagnosis
        public static final short FILE_FULL                      = (short)0x6A84;                   // Not enough memory space in the file
        public static final short LOGICAL_CHANNEL_NOT_SUPPORTED  = (short)0x6881;                   // Card does not support the operation on the specified logical channel
        public static final short SECURE_MESSAGING_NOT_SUPPORTED = (short)0x6882;                   // Card does not support secure messaging
        public static final short WARNING_STATE_UNCHANGED        = (short)0x6200;                   // Warning, card state unchanged
        public static final short LAST_COMMAND_EXPECTED          = (short)0x6883;                   // Last command in chain expected
        public static final short COMMAND_CHAINING_NOT_SUPPORTED = (short)0x6884;                   // Command chaining not supported
        public static final short AUTHENTICATION_FAILURE         = (short)0x6300;                   // (Not a JC standard name/value) Home brew.
    }


    public static byte[] BuildResponse(short sSW) {                                                 // Helper for empty response construction
        byte[] baResponse = new byte[2];
        baResponse[0] = (byte)(sSW >> 8);
        baResponse[1] = (byte)(sSW);
        return baResponse;
    }

    public static byte[] BuildResponse(byte[] baData, short sSW) {                                  // Helper for data + response construction
        byte[] baResponse = new byte[baData.length + 2];
        arraycopy(baData, 0, baResponse, 0, baData.length);
        baResponse[baData.length] = (byte)(sSW >> 8);
        baResponse[baData.length + 1] = (byte)(sSW);
        return baResponse;
    }


    public static class ExitException extends Exception {                                           // Response Exit StatusReportingException
        private short   sExcuse;
        private byte[]  baData;
        public ExitException() { super(); }

        public byte[] GetResponse() {
            if (baData == null) { return Apdu.BuildResponse(sExcuse);         }
            else                { return Apdu.BuildResponse(baData, sExcuse); }
        }

        public void Throw(byte[] baData, short sStatusWord) throws ExitException {
            this.baData = baData;;                                                             // avoids a lot of new and dispose operations.
            this.sExcuse = sStatusWord;
            throw this;
        }

        public void Throw(short sStatusWord) throws ExitException {
            this.baData = null;
            this.sExcuse = sStatusWord;
            throw this;
        }

    }



}
