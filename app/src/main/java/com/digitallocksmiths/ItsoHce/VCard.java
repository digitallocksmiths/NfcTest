package com.digitallocksmiths.ItsoHce;

import static java.lang.System.arraycopy;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Scanner;

import org.json.JSONException;
import org.json.JSONObject;

import com.digitallocksmiths.ItsoHce.Itso.Shell;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;
import com.digitallocksmiths.ItsoHce.VcardCmd2.Cmd2;
import com.digitallocksmiths.ItsoHce.VcardCmd11.Cmd11;
import com.digitallocksmiths.ItsoHce.VcardCmd12.Cmd12;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public abstract class VCard {
    private static final String TAG = "VCard";


    // =============================================================================================
    // Main Class behaviour
    //

    // Image Filenames/identifiers
    static final String szKeyStore  = "AndroidKeyStore";
    static final String szFileNameA = "VCardImageA";
    static final String szFileNameB = "VCardImageB";


    // Image save/restore variables                                     // Static because we only have one file/one AID
    protected static  Nvm         nvm;                                  // The memory storage for the image.
    private   static  KeyStore    keyStore;                             // The key storage for the image.
    private   static  SecretKey   KeyB;                                 // The key used to encrypt the imageB.
    private   static  SecretKey   KeyA;                                 // The key used to encrypt the imageA.
    private   static  int         iAgeA = 0;                            // The age of Image A
    private   static  int         iAgeB = 0;                            // The age of Image B

    public            String      szFilename        = null;             // Name of the file we've read JSON stuff from.
    public    static  Shell       shell;

    // ==================================================
    // Image variables used in this superclass.
    // Stored and recovered from the image file vis the
    // serializer functions.
    private static  int         iAge = 0;                               // age of this file ( monotonic counter or updates.)
    public  static  byte[]      baShell = new byte[24];                 // will/must be 0x18 bytes (i.e. no MCRN)
    public  static  byte[]      baName  = new byte[32];                 // space for the title of the card.
    public  static  byte[]      baTitle = new byte[32];                 // space for the title of the card.
    private final   int         iNvmSizeSuper = 92;                     // size of the above savable data.



    // ===============================================
    // Initialize:
    //      One-off setup called by the owning application.
    //      Called on application load.
    // ===============================================
    public static void Initialize(String szImageDirectory) throws VirtualCardException {                                       // set up the key store and image storage.
        nvm      = new Nvm(szImageDirectory);
        try {
            keyStore = KeyStore.getInstance(szKeyStore);
            keyStore.load(null);
            KeyA = (SecretKey) keyStore.getKey(szFileNameA, null);                                  // using file name as the key alias here
            KeyB = (SecretKey) keyStore.getKey(szFileNameB, null);                                  // same again.
            if ((KeyA == null) || (KeyB == null)) {
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, szKeyStore);
                keyGen.init(new KeyGenParameterSpec.Builder(szFileNameA, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).build());
                keyGen.generateKey();
                KeyA = (SecretKey) keyStore.getKey(szFileNameA, null);
                keyGen.init(new KeyGenParameterSpec.Builder(szFileNameB, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).build());
                keyGen.generateKey();
                KeyB = (SecretKey) keyStore.getKey(szFileNameB, null);
            }
        }
        catch (  java.security.cert.CertificateException |
                 java.io.IOException |
                 java.security.KeyStoreException |
                 java.security.NoSuchAlgorithmException |
                 java.security.UnrecoverableKeyException |
                 java.security.InvalidAlgorithmParameterException |
                 java.security.NoSuchProviderException |
                 java.security.InvalidParameterException e ) {
            Log.d(TAG, "Key load went tits up");
            throw new VCard.VirtualCardException("VCard: Key load went tits up");
        }

    }




    // ===============================================
    // base class constructor:
    //      Little to do here!
    //
    // ===============================================
    public VCard() throws VCard.VirtualCardException {                                              // constructor invoked via subclass.
        TitleSet("Uninitialized Card Image");
    }


    // ===============================================
    // FactoryLoadImage:
    //      read the encrypted image file then create
    //      and return the appropriate sub-class.
    //
    // ===============================================
    public static VCard FactoryImageLoad() throws VirtualCardException {                             // power up card

        ByteBuffer bufferA = FileReadEncryptedBuffer(Shadow.A);
        ByteBuffer bufferB = FileReadEncryptedBuffer(Shadow.B);
        ByteBuffer buffer  = null;

        iAgeA = iAgeB = 0;
        if ((bufferA != null) && (bufferA.remaining() >= 4)) { iAgeA = bufferA.getInt();  }         // read the images Age (first 4 bytes)
        if ((bufferB != null) && (bufferB.remaining() >= 4)) { iAgeB = bufferB.getInt();  }

        if (iAgeA > iAgeB)              { iAge = iAgeA; buffer = bufferA; }
        else                            { iAge = iAgeB; buffer = bufferB; }

        VCard vc;
        if (((iAgeA != 0) || (iAgeB != 0)) && (buffer != null)) {
            try {
                buffer.get(baShell);                                                                // Read the image's Shell;
                shell = new Shell(baShell);                                                         // Parse the Shell
                switch (shell.getFvc()) {
                    case 0x02:  vc = new Cmd2(); break;
                    case 0x0B:  vc = new Cmd11(); break;
                    case 0x0C:  vc = new Cmd12(); break;
                    default:    vc = new Cmd0(); break;
                }
                buffer.get(baName);                                                                 //                  Name;
                buffer.get(baTitle);                                                                //                  Title;
                vc.ImageDeserialize(buffer);
                return vc;
            }
            catch (Exception e) {
                Log.d(TAG, "FactoryImageLoad: parser failed");                                      // in development, we use 'get' exceptions to recognize faulty images
            }
        }
        return new Cmd0();
    }

    // ===============================================
    // ImageSave:
    //      serialize the current image,
    //      encrypt it and save it.
    //
    // ===============================================
    public void ImageSave() throws VirtualCardException,  VirtualCardException, Exception {
        ByteBuffer buffer = ByteBuffer.allocate(iNvmSizeSuper + ImageGetSize() + 4);        // accumulator for the saved image  super+sub+crc
        buffer.putInt(++iAge);                                                                      // Add super's elements first.  iAge +
        buffer.put(baShell);                                                                        //                              baShell.
        buffer.put(baName);                                                                         //                              baName.
        buffer.put(baTitle);                                                                        //                              baTitle.
        ImageSerialize(buffer);                                                                     // next let the subclass serialize its image
        if (iAgeA > iAgeB) { iAgeB = iAge; FileWriteEncryptedBuffer(Shadow.B, buffer); }            // helper for encrypting and saving the image
        else               { iAgeA = iAge; FileWriteEncryptedBuffer(Shadow.A, buffer); }
    }

    // ===============================================
    // ImageImportJson:
    //      Erase the current image and read a new JSON file VCard description.
    //
    // ===============================================
    public static VCard ImageImportJson(String szJsonFilename) throws JSONException, VirtualCardException {                  // erase old image and create new one from Json description.
        File   file;
        String szJson;
        JSONObject jsonCardImage;

        try {
            file = new File(szJsonFilename);
            Scanner scanner = new Scanner(file, "UTF-8");
            szJson = scanner.useDelimiter("\\A").next();
            jsonCardImage = new JSONObject(szJson);
            scanner.close();
        } catch (IOException e) {
            throw new VirtualCardException("Error opening file: " + szJsonFilename);
        }
        catch (JSONException e) {
            throw new VirtualCardException("Error parsing Json: " + szJsonFilename);
        }

        try {
            VCard vc;

            baShell = DecodeJsonByteArray(jsonCardImage, "baShell");
            shell   = new Shell(baShell);

            switch (shell.getFvc()) {                                                               // Create the appropriate sub-class
                case 2:  vc = new Cmd2();   break;
                case 11: vc = new Cmd11();  break;
                case 12: vc = new Cmd12();  break;
                default: vc = new Cmd0();   break;
            }
            vc.NameSet(jsonCardImage.getString("szName"));
            vc.TitleSet(jsonCardImage.getString("szTitle"));
            vc.JsonParse(jsonCardImage);                                                            // let it parse itself

            nvm.WipeDirectory();                                                                    // parsing went well so delete the old image

            iAge = iAgeA = iAgeB = 0;
            vc.ImageSave();                                                                         // Now save the new one.

           vc.szFilename = file.getName();
            return vc;
        }
        catch (Exception e) {
            throw new VirtualCardException("Error parsing Json: " + szJsonFilename);
        }
    }


    // ===============================================
    // ImageExportJson:
    //      Archive the current Image as a JSON file.
    //
    // ===============================================
    public void ImageExportJson(String szJsonFilename) throws VirtualCardException {
        JSONObject jsonCardImage;
        try {
            jsonCardImage = new JSONObject();
            EncodeJsonByteArray(jsonCardImage, "baShell", baShell);
            jsonCardImage.put ("szName", NameGet());
            jsonCardImage.put ("szTitle", TitleGet());
            JsonExport(jsonCardImage);
        } catch (JSONException e) {
            throw new VirtualCardException("Error exporting Json: " + szJsonFilename);
        }

        String szCardImage = jsonCardImage.toString();
        File file = new File(szJsonFilename);
        try {
            boolean b = file.createNewFile();
            FileWriter writer = new FileWriter(file);
            writer.write(szCardImage);
            writer.close();
            //szSavedAsFilename = file.getName();
        } catch (IOException e) {
            throw new VirtualCardException("Error writing file: " + szJsonFilename);
        }
    };

    protected abstract int      ImageGetSize();                                                     // subclasses indicate their own storage volume requirements
    protected abstract void     ImageDeserialize(ByteBuffer buffer)  throws VirtualCardException;   // subclasses populate their working variables here.
    protected abstract void     ImageSerialize(ByteBuffer buffer);                                  // subclasses serialize their variables here.
    protected abstract void     JsonParse(JSONObject jsonCardImage)  throws JSONException, VirtualCardException; // parse the JSON image into the CM Image
    protected abstract void     JsonExport(JSONObject jsonCardImage) throws JSONException;          // Make a Json String of the CM Image
    protected abstract void     Reset()                              throws VirtualCardException;   // Called on Reset.
    protected abstract byte[]   Select(byte[] baAid);                                               // build the FCI's A5 TLV.
    protected abstract byte[]   Dispatch(byte[] baApdu);                                            // Process the incoming APDU




// =================================================================================================
// =============================================================================================
// Helper classes and static functions
// Helper functions used by the subclasses.
//

    protected static class AuthenticationException extends Exception {                              // manages return logic for authentication failures.
        public AuthenticationException() { super(); }
    }

    public static class VirtualCardException extends Exception {                                    // our type of exception
        public VirtualCardException(String szMsg) {
            super(szMsg);
        }
    }

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
    }

    public static class ISO7816 {                                                                  // ISO7816 constants
        public static final int OFFSET_CLA    = 0;
        public static final int OFFSET_INS    = 1;
        public static final int OFFSET_P1     = 2;
        public static final int OFFSET_P2     = 3;
        public static final int OFFSET_LC     = 4;
        public static final int OFFSET_CDATA  = 5;
    }



    public static class Shadow {
        public static final short A                       = 1;
        public static final short B                       = 2;
    }

    public static byte[] Response(short sSW) {                                                      // Helper for empty response construction
        byte[] baResponse = new byte[2];
        baResponse[0] = (byte)(sSW >> 8);
        baResponse[1] = (byte)(sSW);
        return baResponse;
    }

    public static byte[] Response(byte[] baData, short sSW) {                                       // Helper for data + response construction
        byte[] baResponse = new byte[baData.length + 2];
        System.arraycopy(baData, 0, baResponse, 0, baData.length);
        baResponse[baData.length] = (byte)(sSW >> 8);
        baResponse[baData.length + 1] = (byte)(sSW);
        return baResponse;
    }

    private static byte[] ChecksumCalculate(byte[] baBlob) {
        byte[] baChecksum = new byte[4];
        baChecksum[0] = (byte)0xff;
        baChecksum[1] = (byte)0x00;
        baChecksum[2] = (byte)0xff;
        baChecksum[3] = (byte)0x00;
        for (int i = 0; i < baBlob.length -4 ; i++) {
            baChecksum[0] += baBlob[i];
            baChecksum[1] += baChecksum[0];
            baChecksum[2] += baChecksum[1];
            baChecksum[3] += baChecksum[2];
        }
        return baChecksum;
    }

    private static boolean ChecksumVerify(byte[] baBlob) {
        byte[] baChecksum = ChecksumCalculate(baBlob);
        for (int i = 0; i < 4; i++) {
            if (baChecksum[i] != baBlob[baBlob.length - 4 + i]) {
                return false;
            }
        }
        return true;
    }

    protected static byte[] DecodeStringToByteArray(String szString) {                              // Sz ==> ba
        return Base64.decode(szString, Base64.DEFAULT);
    }
    protected static String EncodeByteArrayToString(byte[] baBlob) {                                // ba ==> Sz
        return Base64.encodeToString(baBlob, Base64.NO_WRAP);
    }
    protected static byte[] DecodeJsonByteArray(JSONObject szJsonCardImage, String szKey) {
        try {
            String S = szJsonCardImage.getString(szKey);
            if (S.equals("null")) {                                                                 // "null" is good base64 for [-98, -23, 101 ] !!!
                return new byte[0];
            }
            return Base64.decode(S, Base64.DEFAULT);
        }
        catch (JSONException e) {
            return null;
        }
    }

    protected static void EncodeJsonByteArray(JSONObject szJsonCardImage, String szKey, byte[] baBlob) {
        try {
            if ((baBlob == null) || baBlob.length == 0) {
                szJsonCardImage.put(szKey, JSONObject.NULL);
                return;
            }
            szJsonCardImage.put(szKey, EncodeByteArrayToString(baBlob));
        }
        catch (JSONException e) {
            return;
        }
    }




    public void   TitleSet(String szTitle) { baTitle = java.util.Arrays.copyOf(szTitle.getBytes(), baTitle.length);   }  // Accessors for strings stored as fixed size byte arrays.
    public String TitleGet()               { return new String(baTitle, StandardCharsets.UTF_8).trim();               }
    public void   NameSet(String szName)   { baName = java.util.Arrays.copyOf(szName.getBytes(), baName.length);      }
    public String NameGet()                { return new String(baName, StandardCharsets.UTF_8).trim();                }


    // ===============================================
    // FileReadEncryptedBuffer:
    //      Read an image file with the appropriate key.
    //      decrypt it and convert it to a ByteBuffer.
    // ===============================================
    private static ByteBuffer FileReadEncryptedBuffer(short AorB)  {

        byte[]      baBuffer;
        SecretKey   key;

        switch (AorB) {
            case Shadow.A:  baBuffer = nvm.Read(szFileNameA);                                              // Read the encrypted file
                key      = KeyA;
                break;
            case Shadow.B:  baBuffer = nvm.Read(szFileNameB);
                key      = KeyB;
                break;
            default:        throw new IllegalStateException("FileReadEncryptedBuffer: Unexpected value: " + AorB);
        }

        if (baBuffer == null) {
            Log.d(TAG, "FileReadEncryptedBuffer: File not found");
            return null;
        }
        if (key == null) {
            Log.d(TAG, "FileReadEncryptedBuffer: Key not found");
            return null;
        }

        // ToDo: Decrypt here
        //try {
        //    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        //    cipher.init(Cipher.DECRYPT_MODE, Key);
        //    baA = cipher.doFinal(ba);                                                             // decrypted file
        //}
        //catch (java.security.NoSuchAlgorithmException |
        //       javax.crypto.NoSuchPaddingException |
        //       java.security.InvalidKeyException |
        //       javax.crypto.BadPaddingException |
        //       javax.crypto.IllegalBlockSizeException ex) {
        //    Log.d(TAG, "Decrypt A cocked up");
        //    baA = new byte[0];
        //}

        if (ChecksumVerify(baBuffer)) {
            return ByteBuffer.wrap(baBuffer);
        }
        else {
            Log.d(TAG, "FileReadEncryptedBuffer: Checksum failed");
            return null;
        }
    }

    // ===============================================
    // FileWriteEncryptedBuffer:
    //      append the checksum and encrypt the buffer.
    //      Then save it to the appropriate file.
    //
    //      not the key change to endure the same key
    //      is not used for the predictably variable file.
    // ===============================================
    private static void FileWriteEncryptedBuffer(short AorB, ByteBuffer buffer)  throws VCard.VirtualCardException, Exception {
        String      szFilename;
        SecretKey   key;

        // ToDo: New Key
        key = null;
        switch (AorB) {
            case Shadow.A: szFilename = szFileNameA;                                              // Read the encrypted file
                KeyA       = key;
                break;
            case Shadow.B: szFilename = szFileNameB;
                key      = KeyB;
                break;
            default:        throw new IllegalStateException("FileWriteEncryptedBuffer: Unexpected value: " + AorB);
        }

        byte[] baBlob = buffer.array();                                                             // construction is complete
        buffer.put(ChecksumCalculate(baBlob));                                                      // Add the checksum

        // ToDo: Encrypt here
        //try {
        //    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");                              // encrypted buffer
        //    cipher.init(Cipher.ENCRYPT_MODE, key);
        //    baBlob = cipher.doFinal(baBlob);
        nvm.Write(szFilename, baBlob);                                                              // Write the encrypted file
    }

    public    static final byte SerializeOverhead = (byte)5;
    protected static final byte ByteSentinel      = (byte)0xA5;

    public static  void SerializeByteArray(ByteBuffer b, byte[] baBlob) {
        b.put(ByteSentinel);
        b.putInt(baBlob.length);
        b.put(baBlob);
    }

    public static  byte[] DeserializeByteArray(ByteBuffer b) throws VirtualCardException {
        if (b.get() != ByteSentinel) {
            throw new VirtualCardException("Corrupt Image File");
        }
        int len = b.getInt();
        byte[] baBlob = new byte[len];
        b.get(baBlob);
        return baBlob;
    }

    protected static boolean ArraysAreEqual(byte[] baA, byte[] baB) {
        if (baA.length != baB.length) {
            return false;
        }
        for (int i = 0; i < baA.length; i++) {
            if (baA[i] != baB[i]) {
                return false;
            }
        }
        return true;
    }

    protected static boolean BytesMatch(byte[] baA, int iOffsetA, byte[] baB, int iOffsetB, int iLen) {
        if (baA.length < iOffsetA + iLen) {               return false; }
        if (baB.length < iOffsetB + iLen) {               return false; }
        for (int i = 0; i < iLen; i++) {
            if (baA[iOffsetA + i] != baB[iOffsetB + i]) { return false; }
        }
        return true;
    }


    protected SecretKey ConstructDesKey(byte[] baKeyMaterial) {
        byte[] baFullSizeKey;

        switch (baKeyMaterial.length) {
            case 24:    baFullSizeKey = baKeyMaterial;
                break;
            case 16:    baFullSizeKey = new byte[24];
                System.arraycopy(baKeyMaterial, 0, baFullSizeKey, 0, 16);
                System.arraycopy(baKeyMaterial, 0, baFullSizeKey, 16, 8);
                break;
            case 8:     baFullSizeKey = new byte[24];
                System.arraycopy(baKeyMaterial, 0, baFullSizeKey, 0, 8);
                System.arraycopy(baKeyMaterial, 0, baFullSizeKey, 8, 8);
                System.arraycopy(baKeyMaterial, 0, baFullSizeKey, 16, 8);
                break;
            default:    return null;
        }

        try {
            DESedeKeySpec keySpec = new DESedeKeySpec(baFullSizeKey);
            SecretKeyFactory mySecretKeyFactory = SecretKeyFactory.getInstance("DESede");
            return mySecretKeyFactory.generateSecret(keySpec);
        }
        catch (Exception e) {
            Log.e(TAG, "MakeKey: " + e.getMessage());
            return null;
        }
    }

    // =============================================================================================
    // TLV support
    //              limitations:   Tags are 1 byte
    //                         :   Lengths  are 1..255
    //                         :   Sorry! but it's simple!

    protected byte[] TlvBuild(byte bTag, byte[] baV) {                                              // *** TlvBuild
        byte[] baTlv;                                                                               //      make a primitive T.L.V.
        if (baV.length <= 127) { baTlv = new byte[2 + baV.length]; }                                //      ? length > 127 needs '1':: len
        else                   { baTlv = new byte[2 + 1 + baV.length]; }                            //        length < 128 is just a simple length
        int iOffset = 0;                                                                            //        Note: Max length catered for here is 255!
        baTlv[iOffset++] = bTag;                                                                    //      insert T
        if (baV.length > 127) { baTlv[iOffset++] = (byte)0x81; }                                    //      insert L
        baTlv[iOffset++] = (byte)baV.length;                                                        //
        System.arraycopy(baV, 0, baTlv, iOffset, baV.length);                                       //      insert V
        return baTlv;                                                                               // return. job done.
    }

    protected byte[] TlvBuild(byte bTag, ArrayList<byte[]> tagList) {                               // *** TlvBuild
        return TlvBuild(bTag, TlvList(tagList));                                                    //
    }                                                                                               //

    protected byte[] TlvList(ArrayList<byte[]> tagList) {                                           // *** TlvList
        int iLen = 0;                                                                               //      TLV element list into byte[]
        for (byte[] baTt : tagList) { iLen += baTt.length; }                                        //      calculate space to return all
        byte[] baA5contents = new byte[iLen];                                                       //      create that much  space
        int iOffset = 0;                                                                            //
        for (byte[] baTt : tagList) {                                                               //      copy each tlv into this space
            System.arraycopy(baTt, 0, baA5contents, iOffset, baTt.length);                          //
            iOffset += baTt.length;                                                                 //
        }                                                                                           //
        return baA5contents;                                                                        // return with a job done well!
    }                                                                                               //


    protected byte[] WrapAsFci(byte[] baAid, byte[] baTlvA5) {                                      // build 6F <len> opt<aid> <a5>

        boolean f6F_Long;
        if (baAid != null) {  f6F_Long = ( (2 + baAid.length + baTlvA5.length) > 127); }            // assumes AID len < 127.
        else               {  f6F_Long = (                     baTlvA5.length  > 127); }            // no AID here

        byte[] baFci = new byte[((f6F_Long) ? 3:2) +                                                // size of the whole
                                ((baAid != null) ? (2 + baAid.length) : 0 ) +                       //
                                baTlvA5.length];                                                    //

        int iOffset=0;                                                                              // Start filling it...
        baFci[iOffset++] = 0x6F;                                                                    // 6F : FCI tag
        if (f6F_Long) { baFci[iOffset++] = (byte)0x81; }                                            //    optional extended len
        baFci[iOffset++] = (byte)(baFci.length-iOffset);                                            //    len
        if (baAid != null) {                                                                        //    optional AID
            baFci[iOffset++] = (byte) 0x84;                                                         //        84 : tag
            baFci[iOffset++] = (byte) baAid.length;                                                 //           len
            arraycopy(baAid, 0, baFci, iOffset, baAid.length);                                      //           body
            iOffset += baAid.length;                                                                //
        }
        arraycopy(baTlvA5, 0, baFci, iOffset, baTlvA5.length);                                      //         A5: T, L, & V
        return baFci;
    }




}
