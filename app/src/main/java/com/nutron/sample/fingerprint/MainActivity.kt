package com.nutron.sample.fingerprint

import android.os.Build
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*


class MainActivity : AppCompatActivity() {

    private val TAG = "MainActivity"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        authenWithFingerprint()

        refreshButton.setOnClickListener {
            authenWithFingerprint()
        }
    }

    private fun authenWithFingerprint() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val fingerprintHandler = FingerprintHandler(this)
            fingerprintHandler.init()
            fingerprintHandler.startAuth()
        }
    }

}
