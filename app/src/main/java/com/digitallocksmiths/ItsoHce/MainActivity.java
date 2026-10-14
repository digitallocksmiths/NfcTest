package com.digitallocksmiths.ItsoHce;

import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.View;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
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
        findViewById(R.id.buttonClose).setOnClickListener(this::CloseButton);

        TextView tv = findViewById(R.id.txtquestion);
        tv.setMovementMethod(ScrollingMovementMethod.getInstance());
        tv.setMovementMethod(new ScrollingMovementMethod());

        tv.append("NFC HCE Service is active.\n");
        tv.append("AID: F0010203040506\n");

        try {
            VCard.Initialize(GetImageDirectory());                                                      // set up the classes NVM
            vcard = VCard.FactoryImageLoad();                                                           // Load the active CM image
        } catch (VCard.VirtualCardException e) {
            Log.d(TAG, "onCreate: Trouble loading image: " + e.getMessage());
            throw new RuntimeException(e);
        }

        tv.append("Running: " + vcard.TitleGet() + "\n");

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
        try {
            vcard = VCard.ImageImportJson(szJsonFilename);
            Print("Image load: " + vcard.szFilename + "\n");
            Print("Running: " + vcard.TitleGet() + "\n");
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
    }

    private void ExportImage(String szJsonFilename) {
        if (vcard != null) {
            try {
                    vcard.ImageExportJson(szJsonFilename);
                    Print("Image save: " + vcard.szSavedAsFilename + "\n");
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

    public void SaveButton(View v) {
        Print("Save\n");
        String szFilename = GetAppPublicDirectory() +  File.separator + szCardSnapshot;
        ExportImage(szFilename);
    }


}
