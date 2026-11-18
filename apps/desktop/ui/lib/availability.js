// How the window reads what the shell says about the engine: which views can be used, and which engine
// information to keep.

/**
 * The engine information to keep after the shell answered engine_info. A reply whose only news is "the engine was
 * serving another request, so I could not take it to start it" (ENGINE_BUSY) says nothing about whether the engine
 * can start or what it lists. Showing it as "cannot start" would be false, so it does not replace what is already
 * known; with nothing known yet it is all there is, and is kept. A real start failure always replaces.
 */
export function adoptInfo(previous, next) {
  const busy = next?.start?.ok === false && next.start.error?.code === 'ENGINE_BUSY';
  return busy && previous ? previous : next;
}

/**
 * Which views can be used, decided from what the engine listed (tools/list) and from whether it could start.
 *
 * An EMPTY list is not "the engine lists nothing". The shell reports an empty list whenever no engine process is
 * running at that instant: before the first start, and while a settings change is restarting it (the change ends the
 * process and clears what it had listed). That says nothing about the tools, so it must not grey the views out: a
 * button that is dead for a second after "apply" is a window that ignores the user, and the view's own call will
 * start the engine and show its real error. A view is unavailable only when the engine could not start, or when it
 * listed tools and some tool the view needs is not among them.
 */
export function viewAvailability(info, tools, needs) {
  if (!info) return { available: true, missing: [] };
  const startFailed = info.start?.ok === false;
  const listed = startFailed ? [] : (tools ?? []);
  if (!startFailed && listed.length === 0) return { available: true, missing: [] };
  const missing = needs.filter((tool) => !listed.includes(tool));
  return { available: missing.length === 0, missing };
}
