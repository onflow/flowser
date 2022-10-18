import { autoUpdater } from "electron-updater";
import { dialog } from "electron";

export type RegisterListenersOptions = {
  silent?: boolean;
};

export class AppUpdateService {
  async checkForUpdatesAndNotify(
    options: RegisterListenersOptions
  ): Promise<void> {
    this.registerListeners(options);
    await autoUpdater.checkForUpdatesAndNotify();
  }

  private registerListeners(options: RegisterListenersOptions) {
    autoUpdater.autoDownload = false;

    autoUpdater.on("checking-for-update", () => {
      console.log("Checking for update...");
    });

    autoUpdater.on("download-progress", (progress) => {
      console.log(`Download speed ${progress.bytesPerSecond}`);
      console.log(
        `Downloaded ${progress.percent}% (${progress.transferred}/${progress.total})`
      );
    });

    autoUpdater.on("update-available", () => {
      dialog
        .showMessageBox({
          type: "info",
          title: "Found Updates",
          message: "Found updates, do you want update now?",
          buttons: ["Sure", "No"],
        })
        .then((buttonIndex) => {
          if (buttonIndex.response === 0) {
            autoUpdater.downloadUpdate();
          }
        });
    });

    autoUpdater.once("update-not-available", () => {
      if (!options.silent) {
        dialog.showMessageBox({
          title: "No Updates",
          message: "Current version is up-to-date.",
        });
      }
    });

    autoUpdater.once("update-downloaded", () => {
      dialog
        .showMessageBox({
          title: "Install Updates",
          message: "Updates downloaded, application will be quit for update...",
        })
        .then(() => {
          setImmediate(() => autoUpdater.quitAndInstall());
        });
    });

    autoUpdater.on("error", (error) => {
      console.log("Error in auto-updater:", error);
      if (!options.silent) {
        dialog.showErrorBox(
          "Update error",
          error == null ? "unknown" : (error.stack || error).toString()
        );
      }
    });
  }
}
