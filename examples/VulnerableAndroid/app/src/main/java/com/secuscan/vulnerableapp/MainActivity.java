package com.secuscan.vulnerableapp;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.sqlite.SQLiteDatabase;
import android.os.Bundle;
import android.util.Log;
import android.webkit.WebSettings;
import android.webkit.WebView;
import androidx.appcompat.app.AppCompatActivity;

import java.io.FileOutputStream;

public class MainActivity extends AppCompatActivity {

    // HARDCODED SECRETS
    private static final String API_KEY = "sk_live_1234567890abcdef123yOuRsEcReT";
    private static final String AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 1. INSECURE LOGGING
        Log.d("API_KEY_LEAK", "Using API key: " + API_KEY);

        // 2. INSECURE DATA STORAGE (WORLD_READABLE is deprecated but highly insecure)
        try {
            SharedPreferences prefs = getSharedPreferences("user_data", Context.MODE_WORLD_READABLE);
            prefs.edit().putString("password", "super_secret_password_123").apply();

            FileOutputStream fos = openFileOutput("secrets.txt", Context.MODE_WORLD_READABLE);
            fos.write("credit_card:4111222233334444".getBytes());
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 3. INSECURE WEBVIEW CONFIGURATION (XSS vulnerability)
        WebView webView = findViewById(R.id.webview);
        if (webView != null) {
            WebSettings webSettings = webView.getSettings();
            webSettings.setJavaScriptEnabled(true); // Risky on untrusted content
            webSettings.setAllowUniversalAccessFromFileURLs(true); // Exposes local files

            // Loading unencrypted HTTP content
            webView.loadUrl("http://www.example.com");
        }

        // 4. SQL INJECTION (Raw string concatenation inside execSQL)
        String userInput = getIntent().getStringExtra("username");
        if (userInput != null) {
            SQLiteDatabase db = openOrCreateDatabase("vulnerable.db", MODE_PRIVATE, null);
            // Vulnerable to SQLi
            db.execSQL("INSERT INTO Users (Name) VALUES ('" + userInput + "');");
            db.close();
        }

        // 5. INSECURE INTENT COMPONENT (Broadcasting sensitive data)
        Intent intent = new Intent("com.example.UPDATE_USER");
        intent.putExtra("user_session_token", "abc123xyz890");
        sendBroadcast(intent); // Without permission restriction, any app can read this
    }
}
