// The only place the window touches the shell. Everything else imports from here, so the rest of the
// code can be exercised without a window.
function tauri() {
  const api = globalThis.__TAURI__;
  if (!api) throw new Error('this page is not running inside the MeguvizDexDash shell');
  return api;
}

export function invoke(command, args) {
  return tauri().core.invoke(command, args);
}

export async function listen(event, handler) {
  return tauri().event.listen(event, (e) => handler(e.payload));
}

let counter = 0;
export function newCallId(label) {
  counter += 1;
  return `${label}-${Date.now().toString(36)}-${counter}`;
}
