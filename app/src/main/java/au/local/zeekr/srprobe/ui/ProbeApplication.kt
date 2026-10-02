package au.local.zeekr.srprobe.ui

import android.app.Application

class ProbeApplication : Application() {
    lateinit var vm: DiagnosticsViewModel
        private set

    override fun onCreate() {
        super.onCreate()
        vm = DiagnosticsViewModel(this)
        vm.recorder.log("7X SR Probe v0.1.1 started. READ ONLY.")
    }
}
