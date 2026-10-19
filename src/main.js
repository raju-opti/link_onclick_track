import {
  createInstance,
  createPollingProjectConfigManager,
  createBatchEventProcessor,
  createLogger,
  INFO,
} from '@optimizely/optimizely-sdk';

const SDK_KEY = import.meta.env.VITE_OPTIMIZELY_SDK_KEY;
const EVENT_KEY = 'eve';
const EVENT_KEY_BEACON = 'beacon';
const USER_ID = 'test-user' + Math.random();

const optimizely = createInstance({
  projectConfigManager: createPollingProjectConfigManager({
    sdkKey: SDK_KEY,
  }),
  eventProcessor: createBatchEventProcessor({
    batchSize: 10,
    flushInterval: 60_000,
  }),
  logger: createLogger({ level: INFO }),
});

const status = document.querySelector('#status');

optimizely
  .onReady()
  .then(() => {
    status.textContent = 'Optimizely ready. Page load event tracked.';
    const user = optimizely.createUserContext(USER_ID);
    const decision = user.decide('beacon_test');
    console.log(decision.variationKey);
    optimizely.track(EVENT_KEY, USER_ID, undefined, { source: 'page_load' });
  })
  .catch((err) => {
    status.textContent = `Optimizely failed to initialize: ${err.message}`;
  });

document.querySelector('#google-link').addEventListener('click', () => {
  // The event is queued in the batch processor. On navigation, the SDK closes
  // itself on `pagehide` and flushes queued events using navigator.sendBeacon.
  optimizely.track(EVENT_KEY_BEACON, USER_ID, undefined, { source: 'link_click' });
});
