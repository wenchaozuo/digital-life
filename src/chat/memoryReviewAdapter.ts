export interface ICloseableController {
  closeReviewPanel(): boolean;
}

export interface ViewActions {
  showMemoryPanel: { value: boolean };
  showUnconfirmedHint: { value: boolean };
}

export function createClosePanelHandler(
  controller: ICloseableController,
  actions: ViewActions
): () => void {
  return () => {
    const hasUnconfirmed = controller.closeReviewPanel();
    if (hasUnconfirmed) {
      actions.showUnconfirmedHint.value = true;
    }
    actions.showMemoryPanel.value = false;
  };
}
