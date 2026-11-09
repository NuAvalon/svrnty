/** Delivery receipt copy: the agreed lines. Do not paraphrase. */

export const DELIVERY_COPY = {
  title: 'Delivery receipts',
  globalLine: 'Lets people see that your device received their notes, and roughly when you were online.',
  contactLine: 'Lets this person see that your device received their note, and roughly when you were online.',
  on: 'On',
  off: 'Off',
  followDefault: 'Follow my setting',
  upgradeNotice:
    'Delivery receipts are on. They let people see that your device received their notes, and roughly when you were online. You can turn them off in Settings.',
  upgradeNoticeDismiss: 'OK',
  restoreAsk:
    'Should this device let people see that it received their notes, and roughly when you were online? No receipts go out until you choose.',
  restoreYes: 'Yes',
  restoreNo: 'No',
  writeFailed: "That didn't save. Your setting is shown as it is stored.",
  unreadable: "This device couldn't read your delivery setting, so no receipts go out until it can.",
} as const;
