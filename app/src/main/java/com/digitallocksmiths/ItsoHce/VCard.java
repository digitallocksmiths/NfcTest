package com.digitallocksmiths.ItsoHce;

import static java.lang.System.arraycopy;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import org.json.JSONException;
import org.json.JSONObject;

import com.digitallocksmiths.ItsoHce.Itso.Shell;
import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;
import com.digitallocksmiths.ItsoHce.VcardCmd2.Cmd2;
import com.digitallocksmiths.ItsoHce.VcardCmd11.Cmd11;
import com.digitallocksmiths.ItsoHce.VcardCmd12.Cmd12;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.security.auth.DestroyFailedException;

public abstract class VCard {
    private static final String TAG = "VCard";


    // =============================================================================================
    // Main Class behaviour
    //

    // Image Filenames/identifiers
    static final String szKeyStore   = "AndroidKeyStore";
    static final String szFileNameA  = "VCardImageA";
    static final String szFileNameB  = "VCardImageB";
    static final String szActiveCard = "ActiveCard";                    // file in the image root holding the active card's id
    static final String szImageCipher = "AES/GCM/NoPadding";            // image file encryption
    static final int    iGcmIvSize    = 12;                             // bytes of IV at the start of an image file
    static final int    iGcmTagSize   = 16;                             // bytes of GCM tag at its end


    // Shared by all cards                                              // one key store and one image root per app
    private   static  String      szImageRoot;                          // each card lives in szImageRoot/<UID as hex>/
    private   static  KeyStore    keyStore;                             // The key storage for the images: one key per card per shadow.

    // Image save/restore variables                                     // per card
    protected         Nvm         nvm;                                  // The memory storage for this card's image (null until first saved).
    private           int         iAgeA = 0;                            // The age of Image A
    private           int         iAgeB = 0;                            // The age of Image B

    public            String      szFilename        = null;             // Name of the file we've read JSON stuff from.
    public            Shell       shell;

    // ==================================================
    // Image variables used in this superclass.
    // Stored and recovered from the image file vis the
    // serializer functions.
    private         int         iAge = 0;                               // age of this file ( monotonic counter or updates.)
    public          byte[]      baShell;                                // will/must be 0x18 bytes (i.e. no MCRN)
    public          byte[]      baName  = new byte[32];                 // space for the name of the card.
    public          byte[]      baTitle = new byte[32];                 // space for the title of the card.
    private static final int    iShellSize    = 24;                     // size of baShell in the image.
    private final   int         iNvmSizeSuper = 92;                     // size of the above savable data.



    // ===============================================
    // Initialize:
    //      One-off setup called by the owning application.
    //      Called on application load.
    // ===============================================
    public static void Initialize(String szImageDirectory, String szOldImageDirectory) throws VirtualCardException {          // set up the key store and image storage.
        szImageRoot = szImageDirectory.endsWith(File.separator) ? szImageDirectory : szImageDirectory + File.separator;
        new File(szImageRoot).mkdirs();
        if (szOldImageDirectory != null) { MoveImageRoot(new File(szOldImageDirectory)); }          // images used to live in public storage
        try {
            keyStore = KeyStore.getInstance(szKeyStore);
            keyStore.load(null);
        }
        catch (  java.security.cert.CertificateException |
                 java.io.IOException |
                 java.security.KeyStoreException |
                 java.security.NoSuchAlgorithmException e ) {
            Log.d(TAG, "Key store load went tits up");
            throw new VCard.VirtualCardException("VCard: Key store load went tits up");
        }
        KeyDelete(szFileNameA);                                                                     // the app-wide keys used before keys were per card
        KeyDelete(szFileNameB);
        MigrateLegacyImage();                                                                       // a pre-multicard image moves into its own card directory
    }

    // ===============================================
    // MoveImageRoot:
    //      One-off move of the card store from its old
    //      (public) directory into szImageRoot.
    //      The directories are on different file systems,
    //      so it copies then deletes. A card already in
    //      szImageRoot wins; its old copy is just deleted.
    //      Keys are named by card id, not path, so moved
    //      images still decrypt.
    // ===============================================
    private static void MoveImageRoot(File oldRoot) {
        File[] entries = oldRoot.listFiles();
        if (entries == null) { return; }                                                            // nothing to move
        for (File entry : entries) {
            File target = new File(szImageRoot + entry.getName());
            File moving = new File(szImageRoot + entry.getName() + ".moving");                     // copy here, then rename: target is never half a copy
            TreeDelete(moving);                                                                     //      left by an interrupted earlier attempt
            if (target.exists() || (TreeCopy(entry, moving) && moving.renameTo(target))) {
                TreeDelete(entry);                                                                  // no image left in public storage
                Log.d(TAG, "MoveImageRoot: moved " + entry.getName());
            } else {
                TreeDelete(moving);                                                                 // try again next start-up
                Log.d(TAG, "MoveImageRoot: failed to move " + entry.getName());
            }
        }
        oldRoot.delete();                                                                           // only succeeds once it is empty
    }

    private static boolean TreeCopy(File from, File to) {
        if (from.isDirectory()) {
            File[] children = from.listFiles();
            if ((children == null) || (!to.mkdirs() && !to.isDirectory())) { return false; }
            for (File child : children) {
                if (!TreeCopy(child, new File(to, child.getName()))) { return false; }
            }
            return true;
        }
        try (FileInputStream in = new FileInputStream(from); FileOutputStream out = new FileOutputStream(to)) {
            byte[] baChunk = new byte[4096];
            for (int n; (n = in.read(baChunk)) > 0; ) { out.write(baChunk, 0, n); }
            return true;
        }
        catch (IOException e) {
            return false;
        }
    }

    private static void TreeDelete(File file) {
        File[] children = file.listFiles();                                                         // null for a plain file
        if (children != null) {
            for (File child : children) { TreeDelete(child); }
        }
        file.delete();
    }

    // ===============================================
    // Image keys:
    //      every card has its own key for each shadow,
    //      held in the AndroidKeyStore under the alias
    //      <card id>.VCardImageA|B
    // ===============================================
    private static String KeyAlias(String szCardId, short AorB) {
        return szCardId + "." + ((AorB == Shadow.A) ? szFileNameA : szFileNameB);
    }

    private static String KeyCardId(Nvm cardNvm) {                                                  // the card directory's name is the card id
        return new File(cardNvm.szImageDir).getName();
    }

    private static SecretKey KeyGet(String szAlias, boolean fCreate) throws VirtualCardException {  // null if absent and not created
        try {
            SecretKey key = (SecretKey) keyStore.getKey(szAlias, null);
            if ((key == null) && fCreate) {
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, szKeyStore);
                keyGen.init(new KeyGenParameterSpec.Builder(szAlias, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)                                // AES/GCM/NoPadding, as the image encryption will use
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(256)
                        .build());
                key = keyGen.generateKey();
                Log.d(TAG, "KeyGet: created " + szAlias);
            }
            return key;
        }
        catch (java.security.GeneralSecurityException | java.security.ProviderException e) {
            Log.d(TAG, "KeyGet: " + szAlias + ": " + e.getMessage());
            throw new VirtualCardException("VCard: key access failed: " + szAlias);
        }
    }

    private static void KeyDelete(String szAlias) {
        try {
            if (keyStore.containsAlias(szAlias)) { keyStore.deleteEntry(szAlias); }
        }
        catch (java.security.KeyStoreException e) {
            Log.d(TAG, "KeyDelete: " + szAlias + ": " + e.getMessage());
        }
    }

    private static void KeysDelete(String szCardId) {                                               // both shadows' keys
        KeyDelete(KeyAlias(szCardId, Shadow.A));
        KeyDelete(KeyAlias(szCardId, Shadow.B));
    }




    // ===============================================
    // base class constructor:
    //      Every card owns its shell.
    //
    // ===============================================
    public VCard(byte[] baShell) throws VCard.VirtualCardException {                                // constructor invoked via subclass.
        this.baShell = baShell;
        this.shell   = new Shell(baShell);
        TitleSet("Uninitialized Card Image");
    }

    private static VCard Construct(byte[] baShell) throws VirtualCardException {                    // create the sub-class for this shell's FVC
        switch (new Shell(baShell).getFvc()) {
            case 0x02:  return new Cmd2(baShell);
            case 0x0B:  return new Cmd11(baShell);
            case 0x0C:  return new Cmd12(baShell);
            default:    return new Cmd0();
        }
    }


    // ===============================================
    // Card identity:
    //      A card is identified by its UID as a hex
    //      string.
    //      Cards without a UID fall back to the ISRN.
    // ===============================================
    protected byte[] UidGet() { return null; }                                                      // subclasses with a UID override this

    public String CardIdGet() {
        byte[] baUid = UidGet();
        return HexString(((baUid != null) && (baUid.length > 0)) ? baUid : shell.getIsrn());
    }

    private static String HexString(byte[] ba) {
        StringBuilder sb = new StringBuilder();
        for (byte b : ba) { sb.append(String.format("%02X", b)); }
        return sb.toString();
    }


    // ===============================================
    // FactoryLoadImage:
    //      read the card's encrypted image file then
    //      create and return the appropriate sub-class.
    //      A missing or unreadable card gives CMD0.
    // ===============================================
    public static VCard FactoryImageLoad(String szCardId) throws VirtualCardException {             // power up card
        if (szCardId != null) {
            File dir = new File(szImageRoot + szCardId);
            if (dir.isDirectory()) {                                                                // don't let Nvm create a directory for an unknown card
                VCard vc = ImageLoad(new Nvm(dir.getPath()));
                if (vc != null) { return vc; }
            }
        }
        return new Cmd0();
    }

    private static VCard ImageLoad(Nvm cardNvm) {                                                   // null if neither shadow holds a valid image
        int[]      aiAge  = new int[2];
        ByteBuffer buffer = ImageNewest(cardNvm, aiAge);
        if (buffer != null) {
            try {
                byte[] baShell = new byte[iShellSize];
                buffer.get(baShell);                                                                // Read the image's Shell;
                VCard vc = Construct(baShell);                                                      //      the shell picks the sub-class
                buffer.get(vc.baName);                                                              //                  Name;
                buffer.get(vc.baTitle);                                                             //                  Title;
                vc.ImageDeserialize(buffer);
                vc.nvm   = cardNvm;
                vc.iAgeA = aiAge[0];
                vc.iAgeB = aiAge[1];
                vc.iAge  = Math.max(aiAge[0], aiAge[1]);
                return vc;
            }
            catch (Exception e) {
                Log.d(TAG, "ImageLoad: parser failed");                                             // in development, we use 'get' exceptions to recognize faulty images
            }
        }
        return null;
    }

    private static ByteBuffer ImageNewest(Nvm cardNvm, int[] aiAge) {                               // the newer of the A/B shadows, positioned after its age
        ByteBuffer bufferA = FileReadEncryptedBuffer(cardNvm, Shadow.A);
        ByteBuffer bufferB = FileReadEncryptedBuffer(cardNvm, Shadow.B);
        aiAge[0] = aiAge[1] = 0;
        if ((bufferA != null) && (bufferA.remaining() >= 4)) { aiAge[0] = bufferA.getInt();  }      // read the images Age (first 4 bytes)
        if ((bufferB != null) && (bufferB.remaining() >= 4)) { aiAge[1] = bufferB.getInt();  }
        if ((aiAge[0] == 0) && (aiAge[1] == 0)) { return null; }
        return (aiAge[0] > aiAge[1]) ? bufferA : bufferB;
    }

    // ===============================================
    // ImageSave:
    //      serialize the current image,
    //      encrypt it and save it.
    //
    // ===============================================
    public void ImageSave() throws VirtualCardException,  VirtualCardException, Exception {
        if (nvm == null) { nvm = new Nvm(szImageRoot + CardIdGet()); }                              // first save: the card's directory is named by its UID
        ByteBuffer buffer = ByteBuffer.allocate(iNvmSizeSuper + ImageGetSize() + 4);        // accumulator for the saved image  super+sub+crc
        buffer.putInt(++iAge);                                                                      // Add super's elements first.  iAge +
        buffer.put(baShell);                                                                        //                              baShell.
        buffer.put(baName);                                                                         //                              baName.
        buffer.put(baTitle);                                                                        //                              baTitle.
        ImageSerialize(buffer);                                                                     // next let the subclass serialize its image
        if (iAgeA > iAgeB) { iAgeB = iAge; FileWriteEncryptedBuffer(nvm, Shadow.B, buffer); }       // helper for encrypting and saving the image
        else               { iAgeA = iAge; FileWriteEncryptedBuffer(nvm, Shadow.A, buffer); }
    }

    // ===============================================
    // ImageImportJson:
    //      Read a JSON file VCard description and store it
    //      as a card. A card with the same UID is replaced.
    //
    // ===============================================
    public static VCard ImageImportJson(String szJsonFilename) throws JSONException, VirtualCardException {                  // create a card from a Json description.
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
            VCard vc = Construct(DecodeJsonByteArray(jsonCardImage, "baShell"));                    // Create the appropriate sub-class
            vc.NameSet(jsonCardImage.getString("szName"));
            vc.TitleSet(jsonCardImage.getString("szTitle"));
            vc.JsonParse(jsonCardImage);                                                            // let it parse itself

            vc.nvm = new Nvm(szImageRoot + vc.CardIdGet());                                         // parsing went well so this UID's directory
            vc.nvm.WipeDirectory();                                                                 //      loses any older image of the same card
            KeysDelete(vc.CardIdGet());                                                             //      and its keys: the new image gets fresh ones
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


    // =============================================================================================
    // Card store
    //      szImageRoot/<card id>/VCardImageA|B     one directory per card
    //      szImageRoot/ActiveCard                  id of the card the service presents
    //

    public static class CardInfo {                                                                  // what the card picker shows
        public final String szId;
        public final String szName;
        public final String szTitle;
        CardInfo(String szId, String szName, String szTitle) { this.szId = szId; this.szName = szName; this.szTitle = szTitle; }
    }

    public static ArrayList<CardInfo> CardList() {                                                  // all stored cards, in id order
        ArrayList<CardInfo> cards = new ArrayList<>();
        File[] dirs = new File(szImageRoot).listFiles(File::isDirectory);
        if (dirs == null) { return cards; }
        Arrays.sort(dirs);
        for (File dir : dirs) {
            CardInfo info = ImagePeek(dir.getName());
            if (info != null) { cards.add(info); }
        }
        return cards;
    }

    private static CardInfo ImagePeek(String szCardId) {                                            // read just the name and title, no secrets
        ByteBuffer buffer = ImageNewest(new Nvm(szImageRoot + szCardId), new int[2]);
        if (buffer == null) { return null; }
        try {
            byte[] baName  = new byte[32];
            byte[] baTitle = new byte[32];
            buffer.position(buffer.position() + iShellSize);                                        // skip the shell
            buffer.get(baName);
            buffer.get(baTitle);
            return new CardInfo(szCardId, new String(baName,  StandardCharsets.UTF_8).trim(),
                                          new String(baTitle, StandardCharsets.UTF_8).trim());
        }
        catch (Exception e) {
            return null;
        }
    }

    public static String ActiveCardGet() {                                                          // null if none chosen yet
        try (BufferedReader reader = new BufferedReader(new FileReader(szImageRoot + szActiveCard))) {
            String szCardId = reader.readLine();
            return ((szCardId == null) || szCardId.trim().isEmpty()) ? null : szCardId.trim();
        }
        catch (IOException e) {
            return null;
        }
    }

    public static void ActiveCardSet(String szCardId) throws VirtualCardException {                 // write then rename, so a reader never sees half a file
        File tmp = new File(szImageRoot + szActiveCard + ".tmp");
        try (FileWriter writer = new FileWriter(tmp)) {
            writer.write(szCardId);
        }
        catch (IOException e) {
            throw new VirtualCardException("Error writing active card");
        }
        if (!tmp.renameTo(new File(szImageRoot + szActiveCard))) {
            throw new VirtualCardException("Error setting active card");
        }
    }

    private static void MigrateLegacyImage() {                                                      // single image in the root (pre-multicard) => its own card
        File fileA = new File(szImageRoot + szFileNameA);
        File fileB = new File(szImageRoot + szFileNameB);
        if (!fileA.exists() && !fileB.exists()) { return; }

        VCard vc = ImageLoad(new Nvm(szImageRoot));
        if (vc == null) {
            Log.d(TAG, "MigrateLegacyImage: unreadable, left in place");
            return;
        }
        String szCardId = vc.CardIdGet();
        vc.Dispose();
        File dir = new File(szImageRoot + szCardId);
        dir.mkdirs();
        if (fileA.exists()) { fileA.renameTo(new File(dir, szFileNameA)); }
        if (fileB.exists()) { fileB.renameTo(new File(dir, szFileNameB)); }
        if (ActiveCardGet() == null) {
            try                             { ActiveCardSet(szCardId); }
            catch (VirtualCardException e)  { Log.d(TAG, "MigrateLegacyImage: " + e.getMessage()); }
        }
        Log.d(TAG, "MigrateLegacyImage: moved to card " + szCardId);
    }

    // =============================================================================================
    // Card deletion
    //      The subclass decides whether its image may be deleted (DeleteCheck);
    //      VCard applies that decision. The caller supplies the user interaction.
    //
    public enum DeletePolicy {
        OK,                                                                                         // delete without asking
        ASK,                                                                                        // warn the user, who may cancel
        FORBID                                                                                      // tell the user it cannot be deleted
    }

    public interface DeleteUi {
        void Ask(String szPrompt, Runnable onConfirm);                                              // run onConfirm only if the user agrees
        void Forbid(String szReason);                                                               // tell the user why the card stays
        void Deleted(String szCardId);                                                              // the card's image has gone
    }

    public void Delete(DeleteUi ui) {
        if (nvm == null) {                                                                          // e.g. the CMD0 stand-in: nothing stored
            ui.Forbid("There is no stored card to delete.");
            return;
        }
        String szCard = NameGet() + ": " + TitleGet() + " (" + CardIdGet() + ")";
        switch (DeleteCheck()) {
            case OK:
                ImageDelete(ui);
                break;
            case ASK:
                ui.Ask("Delete card " + szCard + "?\nThe card image cannot be recovered.", () -> ImageDelete(ui));
                break;
            case FORBID:
            default:
                ui.Forbid("Card " + szCard + " cannot be deleted.");
                break;
        }
    }

    private void ImageDelete(DeleteUi ui) {                                                         // remove the image files and the card's directory
        String szCardId = new File(nvm.szImageDir).getName();                                       // the directory, not the UID, names the stored card
        nvm.WipeDirectory();
        if (!new File(nvm.szImageDir).delete()) { Log.d(TAG, "ImageDelete: directory not removed"); }
        nvm = null;
        KeysDelete(szCardId);                                                                       // the image's keys go with it

        if (szCardId.equals(ActiveCardGet())) {                                                     // the default card has gone: promote another, if any
            ArrayList<CardInfo> cards = CardList();
            if (cards.isEmpty()) {
                if (!new File(szImageRoot + szActiveCard).delete()) { Log.d(TAG, "ImageDelete: ActiveCard not removed"); }
            } else {
                try                             { ActiveCardSet(cards.get(0).szId); }
                catch (VirtualCardException e)  { Log.d(TAG, "ImageDelete: " + e.getMessage()); }
            }
        }
        Log.d(TAG, "ImageDelete: deleted card " + szCardId);
        ui.Deleted(szCardId);
    }

    protected abstract int      ImageGetSize();                                                     // subclasses indicate their own storage volume requirements
    protected abstract void     ImageDeserialize(ByteBuffer buffer)  throws VirtualCardException;   // subclasses populate their working variables here.
    protected abstract void     ImageSerialize(ByteBuffer buffer);                                  // subclasses serialize their variables here.
    protected abstract void     JsonParse(JSONObject jsonCardImage)  throws JSONException, VirtualCardException; // parse the JSON image into the CM Image
    protected abstract void     JsonExport(JSONObject jsonCardImage) throws JSONException;          // Make a Json String of the CM Image
    protected abstract void     Reset()                              throws VirtualCardException;   // Called on Reset.
    protected abstract void     Dispose();                                                          // Overwrite secrets before the instance is abandoned to the GC.
    protected abstract DeletePolicy DeleteCheck();                                                  // May this card's image be deleted?
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

    // =============================================================================================

    public static class ApduExitException extends Exception {                                // Response Exit StatusReportingException
        private short   sExcuse;
        private byte[]  baData;
        public ApduExitException() { super(); }

        public byte[] GetResponse() {
            if (baData == null) { return Response(sExcuse);         }
            else                { return Response(baData, sExcuse); }
        }

        public void Throw(byte[] baData, short sStatusWord) throws ApduExitException {
            this.baData = baData;;                                                             // avoids a lot of new and dispose operations.
            this.sExcuse = sStatusWord;
            throw this;
        }

        public void Throw(short sStatusWord) throws ApduExitException {
            this.baData = null;
            this.sExcuse = sStatusWord;
            throw this;
        }

    }

    protected static final ApduExitException ApduException = new ApduExitException();









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
    private static ByteBuffer FileReadEncryptedBuffer(Nvm cardNvm, short AorB)  {

        byte[]      baBuffer;
        SecretKey   key;

        switch (AorB) {
            case Shadow.A:  baBuffer = cardNvm.Read(szFileNameA);                                              // Read the encrypted file
                break;
            case Shadow.B:  baBuffer = cardNvm.Read(szFileNameB);
                break;
            default:        throw new IllegalStateException("FileReadEncryptedBuffer: Unexpected value: " + AorB);
        }

        if (baBuffer == null) {
            Log.d(TAG, "FileReadEncryptedBuffer: File not found");
            return null;
        }
        String szAlias = KeyAlias(KeyCardId(cardNvm), AorB);
        try {
            key = KeyGet(szAlias, false);                                                           // reading never creates a key
        }
        catch (VirtualCardException e) {
            key = null;
        }
        if (key == null) {                                                                          // no key: the image cannot be decrypted
            Log.d(TAG, "FileReadEncryptedBuffer: Key not found");
            return null;
        }

        if (baBuffer.length < iGcmIvSize + iGcmTagSize) {
            Log.d(TAG, "FileReadEncryptedBuffer: File too short");
            return null;
        }
        try {                                                                                       // file = IV : ciphertext : tag
            Cipher cipher = Cipher.getInstance(szImageCipher);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(iGcmTagSize * 8, baBuffer, 0, iGcmIvSize));
            cipher.updateAAD(szAlias.getBytes(StandardCharsets.UTF_8));                             // the file must belong to this card and shadow
            baBuffer = cipher.doFinal(baBuffer, iGcmIvSize, baBuffer.length - iGcmIvSize);          // decrypted image; a bad tag throws
        }
        catch (java.security.GeneralSecurityException | java.security.ProviderException e) {
            Log.d(TAG, "FileReadEncryptedBuffer: Decrypt failed: " + e.getMessage());
            return null;
        }

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
    //      AES-GCM with the card's key for this shadow.
    //      The Keystore picks a fresh random IV for
    //      every save, so the key can be reused safely.
    //      The key alias is the AAD, binding the file
    //      to its card and shadow.
    //      File = IV(12) : ciphertext : tag(16)
    // ===============================================
    private static void FileWriteEncryptedBuffer(Nvm cardNvm, short AorB, ByteBuffer buffer)  throws VCard.VirtualCardException, Exception {
        String      szFilename;
        SecretKey   key;

        switch (AorB) {
            case Shadow.A: szFilename = szFileNameA;                                              // Write the encrypted file
                break;
            case Shadow.B: szFilename = szFileNameB;
                break;
            default:        throw new IllegalStateException("FileWriteEncryptedBuffer: Unexpected value: " + AorB);
        }
        String szAlias = KeyAlias(KeyCardId(cardNvm), AorB);
        key = KeyGet(szAlias, true);                                                                // this card's key for this shadow, made on first save

        byte[] baBlob = buffer.array();                                                             // construction is complete
        buffer.put(ChecksumCalculate(baBlob));                                                      // Add the checksum

        byte[] baFile;
        try {
            Cipher cipher = Cipher.getInstance(szImageCipher);
            cipher.init(Cipher.ENCRYPT_MODE, key);                                                  // the Keystore chooses the IV
            cipher.updateAAD(szAlias.getBytes(StandardCharsets.UTF_8));
            byte[] baIv     = cipher.getIV();
            byte[] baCipher = cipher.doFinal(baBlob);                                               // ciphertext : tag
            baFile = new byte[baIv.length + baCipher.length];
            arraycopy(baIv,     0, baFile, 0,           baIv.length);
            arraycopy(baCipher, 0, baFile, baIv.length, baCipher.length);
        }
        catch (java.security.GeneralSecurityException | java.security.ProviderException e) {
            Log.d(TAG, "FileWriteEncryptedBuffer: Encrypt failed: " + e.getMessage());
            throw new VirtualCardException("VCard: image encryption failed");
        }
        finally {
            Scrub(baBlob);                                                                          // don't leave the plain image to the GC
        }
        cardNvm.Write(szFilename, baFile);                                                          // Write the encrypted file
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


    protected static void Scrub(byte[] ba) {                                                        // overwrite a buffer, null safe
        if (ba != null) { java.util.Arrays.fill(ba, (byte)0); }
    }

    protected static SecretKey Destroy(SecretKey key) {                                             // destroy a key if the provider allows it
        if (key != null) {                                                                          //      SecretKeySpec & DESede keys usually refuse,
            try { key.destroy(); }                                                                  //      so the best we can do then is drop the reference.
            catch (DestroyFailedException e) { /* not supported by this key type */ }
        }
        return null;
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
        finally {
            if (baFullSizeKey != baKeyMaterial) {                                                   // scrub our padded copy; the caller owns baKeyMaterial
                Scrub(baFullSizeKey);
            }
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
