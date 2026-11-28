import { Capacitor } from '@capacitor/core';
import { App } from '@capacitor/app';

export function installAndroidNativeBridge(): void {
  if (!Capacitor.isNativePlatform() || Capacitor.getPlatform() !== 'android') {
    return;
  }

  document.documentElement.classList.add('pin-native-android');

  void App.addListener('backButton', () => {
    const closableSelectors = [
      '#pin-img-lightbox',
      '#pin-msg-action-sheet',
      '#pin-alias-modal',
      '#pin-contacts-popover',
    ];
    for (const sel of closableSelectors) {
      const el = document.querySelector<HTMLElement>(sel);
      if (el) {
        el.remove();
        return;
      }
    }

    if (document.body.classList.contains('pin-mobile-chat-open')) {
      const backBtn = document.getElementById('btn-mobile-back');
      if (backBtn) {
        backBtn.click();
      } else {
        document.body.classList.remove('pin-mobile-chat-open');
      }
      return;
    }

    void App.minimizeApp();
  });
}
