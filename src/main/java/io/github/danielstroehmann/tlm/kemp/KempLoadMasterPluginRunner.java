package io.github.danielstroehmann.tlm.kemp;

import java.io.IOException;

import com.digicert.tlm.SdkContext;
import com.digicert.tlm.SdkRuntime;

/** Entry point started by the TLM sensor ({@code java -jar}); the SDK reads {@code plugin-info.json}. */
public class KempLoadMasterPluginRunner {

    public static void main(String[] args) throws IOException {
        new SdkRuntime(KempLoadMasterPluginRunner.class.getPackageName().toLowerCase())
                .execute(KempLoadMasterPlugin.NAME, new SdkContext());
    }
}
