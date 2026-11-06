package com.digitallocksmiths.ItsoHce;

import android.content.ComponentName;
import android.nfc.NfcAdapter;
import android.nfc.cardemulation.CardEmulation;
import android.os.Build;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.digitallocksmiths.ItsoHce.VcardCmd0.Cmd0;
import com.github.angads25.filepicker.controller.DialogSelectionListener;
import com.github.angads25.filepicker.model.DialogConfigs;
import com.github.angads25.filepicker.model.DialogProperties;
import com.github.angads25.filepicker.view.FilePickerDialog;

import java.io.File;
import java.util.ArrayList;
import java.util.Objects;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MyGui";

    public static String PACKAGE_NAME;

    public byte[] baShell;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        PACKAGE_NAME = getApplicationContext().getPackageName();

        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        findViewById(R.id.buttonLoad).setOnClickListener(this::LoadButton);
        findViewById(R.id.buttonSave).setOnClickListener(this::SaveButton);
        findViewById(R.id.buttonCards).setOnClickListener(this::CardsButton);
        findViewById(R.id.buttonClose).setOnClickListener(this::CloseButton);

        TextView tv = findViewById(R.id.txtquestion);
        tv.setMovementMethod(ScrollingMovementMethod.getInstance());
        tv.setMovementMethod(new ScrollingMovementMethod());

        boolean bRestored = savedInstanceState != null && savedInstanceState.containsKey(LOG_TEXT_KEY);
        if (bRestored) {                                                                                // recreated (e.g. rotation): put the log back
            tv.setText(savedInstanceState.getCharSequence(LOG_TEXT_KEY));
            tv.post(() -> Print(""));                                                                   // scroll to the end once laid out
        } else {
            tv.append("NFC HCE Service is active.\n");
            tv.append("AID: A0000002164954534F2D31\n");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {                      // Android 15+: the Wallet app's observe mode
                tv.append("Note: background taps are blocked by the Wallet app "                      //      silences HCE unless we are in the foreground
                        + "(e.g. Google Wallet). Keep this app open when tapping.\n");
            }
        }

        try {
            VCard.Initialize(GetImageDirectory());                                                      // set up the classes NVM
            vcard = VCard.FactoryImageLoad(VCard.ActiveCardGet());                                      // Load the active CM image
        } catch (VCard.VirtualCardException e) {
            Log.d(TAG, "onCreate: Trouble loading image: " + e.getMessage());
            throw new RuntimeException(e);
        }

        ShowTitle();
    }

    private void ShowTitle() {                                                                      // bold title line above the log shows the card's name
        TextView tvTitle = findViewById(R.id.txtTitle);
        if (vcard == null) { tvTitle.setText(R.string.title_no_card); }
        else { tvTitle.setText(getString(R.string.title_card, vcard.NameGet(), vcard.TitleGet())); }
    }

    // =============================================================================================
    // AID routing
    //      While we are in the foreground our HCE service is the preferred
    //      handler for its AIDs, so another app registering the ITSO AID
    //      cannot trigger the chooser or steal the tap.
    //
    private CardEmulation GetCardEmulation() {                                                      // null if the device has no NFC
        NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
        return (adapter != null) ? CardEmulation.getInstance(adapter) : null;
    }

    @Override
    protected void onResume() {
        super.onResume();
        CardEmulation cardEmulation = GetCardEmulation();
        if (cardEmulation != null) {
            boolean f = cardEmulation.setPreferredService(this, new ComponentName(this, MyHostApduService.class));
            Log.d(TAG, "setPreferredService: " + f);
        }
    }

    @Override
    protected void onPause() {
        CardEmulation cardEmulation = GetCardEmulation();
        if (cardEmulation != null) {
            cardEmulation.unsetPreferredService(this);                                              // hand AID routing back to the system
        }
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        if (vcard != null) {                                                                        // scrub the secrets before the GC gets them
            vcard.Dispose();
            vcard = null;
        }
        super.onDestroy();
    }

    private static final String LOG_TEXT_KEY = "logText";

    @Override
    protected void onSaveInstanceState(@NonNull Bundle outState) {
        super.onSaveInstanceState(outState);
        TextView tv = findViewById(R.id.txtquestion);
        outState.putCharSequence(LOG_TEXT_KEY, tv.getText());
    }

    public void CloseButton(View v) {
        Log.d(TAG, "BUTTONS: User tapped the CloseButton");
        finish();
    }

    public void Print(String szMsg) {
        TextView tv = findViewById(R.id.txtquestion);
        tv.append(szMsg);
        while (tv.canScrollVertically(1)) {
            tv.scrollBy(0, 10);
        }
    }

    // =============================================================================================
    // File management
    //
    private VCard vcard;


    private String szCardSnapshot  = "SnapshotImage.json";
    private String GetAppPrivateDirectory() { return this.getFilesDir().getPath(); }
    private String GetAppPublicDirectory()  { return Objects.requireNonNull(getExternalFilesDir(null)).getPath(); }
    private String GetImageDirectory()      { return Objects.requireNonNull(getExternalFilesDir(null)).getPath() + File.separator + "Image"; }


    private void ImportImage(String szJsonFilename) {
        if (vcard != null) {                                                                        // every path below replaces the image,
            vcard.Dispose();                                                                        //      so scrub the old one first
            vcard = null;
        }
        try {
            vcard = VCard.ImageImportJson(szJsonFilename);
            VCard.ActiveCardSet(vcard.CardIdGet());                                                 // an imported card becomes the default
            Print("Image load: " + vcard.szFilename + " (card " + vcard.CardIdGet() + ")\n");
            ShowTitle();
            return;
        }
        catch (VCard.VirtualCardException e) {
            Print("VirtualCardException: " + e.getMessage() + "\n");
        }
        catch (Exception e) {
            Print("Exception: " + e.getMessage() + "\n");
        }
        Print("Image load failed. Substituting CMD0\n");
        try {
            vcard = new Cmd0();
        }
        catch (VCard.VirtualCardException e) {
            // this will not happen but it keeps the compiler happy!
        }
        ShowTitle();
    }

    private void ExportImage(String szJsonFilename) {
        if (vcard != null) {
            try {
                    vcard.Dispose();                                                                // the service may have updated the image since we
                    vcard = null;                                                                   //      loaded it, so export a fresh copy from NVM
                    vcard = VCard.FactoryImageLoad(VCard.ActiveCardGet());
                    vcard.ImageExportJson(szJsonFilename);
                    //Print("Image save: " + vcard.szSavedAsFilename + "\n");
            }
            catch (Exception e) {
                Print("Exception: " + e.getMessage() + "\n");
            }
        }
    }

    // =================================
    // Load Button
    //      triggers ImportImage(jsonFilename)
    // =================================

    public void LoadButton(View v) {
        //Print("Load\n");

        DialogProperties properties = new DialogProperties();
        properties.selection_type = DialogConfigs.FILE_SELECT;
        properties.selection_mode = DialogConfigs.SINGLE_MODE;
        properties.root = new File(GetAppPublicDirectory());
        properties.error_dir = new File(GetAppPublicDirectory());
        properties.offset = new File(GetAppPublicDirectory());
        properties.extensions = null;

        FilePickerDialog dialog = new FilePickerDialog(MainActivity.this, properties);
        dialog.setTitle("Select an image File");
        dialog.setDialogSelectionListener(new DialogSelectionListener() {
            @Override
            public void onSelectedFilePaths(String[] files) {
                //files is the array of the paths of files selected by the Application User.
                if (files != null && files.length > 0) {
                    Log.d(TAG, "Selected fileName is " + files[0]);
                    //Print("Selected: " + files[0] + "\n");
                    ImportImage(files[0]);
                }
            }

        });
        dialog.show();
    }

    // =================================
    // Cards Button
    //      pick the default card: the one
    //      the service presents to readers.
    // =================================

    public void CardsButton(View v) {
        Log.d(TAG, "BUTTONS: User tapped the CardsButton");
        ArrayList<VCard.CardInfo> cards = VCard.CardList();
        if (cards.isEmpty()) {
            Print("No cards stored. Use Load to import one.\n");
            return;
        }

        String   szActive = VCard.ActiveCardGet();
        String[] aszItems = new String[cards.size()];
        int      iChecked = -1;
        for (int i = 0; i < cards.size(); i++) {
            VCard.CardInfo card = cards.get(i);
            aszItems[i] = getString(R.string.title_card, card.szName, card.szTitle);                // szName: szTitle
            if (card.szId.equals(szActive)) { iChecked = i; }
        }

        new AlertDialog.Builder(this)
                .setTitle(R.string.cards_picker_title)
                .setSingleChoiceItems(aszItems, iChecked, (dialog, which) -> {
                    dialog.dismiss();
                    SelectCard(cards.get(which));
                })
                .setNegativeButton(android.R.string.cancel, null)
                .show();
    }

    private void SelectCard(VCard.CardInfo card) {
        if (vcard != null) {                                                                        // scrub the card we are leaving
            vcard.Dispose();
            vcard = null;
        }
        try {
            VCard.ActiveCardSet(card.szId);                                                         // the service picks it up on the next SELECT
            vcard = VCard.FactoryImageLoad(card.szId);
            Print("Default card: " + card.szName + ": " + card.szTitle + " (" + card.szId + ")\n");
        }
        catch (VCard.VirtualCardException e) {
            Print("VirtualCardException: " + e.getMessage() + "\n");
        }
        ShowTitle();
    }

    public void SaveButton(View v) {
        Print("Save\n");
        String szFilename = GetAppPublicDirectory() +  File.separator + szCardSnapshot;
        ExportImage(szFilename);
    }


}
