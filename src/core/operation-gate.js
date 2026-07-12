export function createOperationGate() {
  let generation = 0;
  let activeToken = null;

  return Object.freeze({
    get busy() {
      return activeToken !== null;
    },

    invalidate() {
      generation += 1;
    },

    begin() {
      if (activeToken !== null) throw new Error('operation already active');
      generation += 1;
      activeToken = generation;
      return activeToken;
    },

    isCurrent(token) {
      return activeToken === token && generation === token;
    },

    finish(token) {
      if (activeToken === token) activeToken = null;
    },
  });
}
