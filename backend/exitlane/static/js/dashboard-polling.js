export function createDashboardPolling({
  request,
  isActive,
  intervalSeconds,
  setTimer = (callback, delay) => window.setTimeout(callback, delay),
  clearTimer = (timer) => window.clearTimeout(timer),
  requestTimeoutMilliseconds = 15000,
}) {
  let timer = null;
  let running = false;
  let inFlight = null;
  let generation = 0;
  let interval = intervalSeconds;

  function cancelTimer() {
    if (timer !== null) clearTimer(timer);
    timer = null;
  }

  function refresh() {
    if (inFlight) return inFlight;
    const controller = new AbortController();
    const timeout = setTimer(() => controller.abort(), requestTimeoutMilliseconds);
    inFlight = Promise.resolve(request({ signal: controller.signal }))
      .finally(() => {
        clearTimer(timeout);
        inFlight = null;
      });
    return inFlight;
  }

  function schedule(expectedGeneration) {
    if (!running || !isActive() || expectedGeneration !== generation) return;
    cancelTimer();
    timer = setTimer(async () => {
      timer = null;
      try {
        await refresh();
      } catch {
        // Rendering owns error communication; polling continues after transient failures.
      } finally {
        schedule(expectedGeneration);
      }
    }, interval * 1000);
  }

  function start() {
    if (!isActive()) {
      stop();
      return;
    }
    if (running) return;
    running = true;
    generation += 1;
    schedule(generation);
  }

  function stop() {
    running = false;
    generation += 1;
    cancelTimer();
  }

  function restart(newIntervalSeconds = interval) {
    interval = newIntervalSeconds;
    stop();
    start();
  }

  return {
    refresh,
    restart,
    start,
    stop,
    isRunning: () => running,
    hasRequestInFlight: () => inFlight !== null,
  };
}
