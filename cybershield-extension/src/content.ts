import type { CsMessage, PageContext } from './types';

const MAX_HTML = 60_000;

function pageContext(): PageContext {
  const selection = (window.getSelection()?.toString() || '').trim();
  let html = '';
  try {
    html = document.documentElement.outerHTML.slice(0, MAX_HTML);
  } catch {
    html = '';
  }
  return {
    url: location.href,
    title: document.title,
    html,
    selection,
    linkCount: document.querySelectorAll('a[href]').length,
  };
}

chrome.runtime.onMessage.addListener((msg: CsMessage, _sender, sendResponse) => {
  if (msg.kind === 'GET_PAGE_CONTEXT') {
    sendResponse(pageContext());
  } else if (msg.kind === 'GET_SELECTION') {
    sendResponse({ selection: (window.getSelection()?.toString() || '').trim() });
  }
  return true;
});
