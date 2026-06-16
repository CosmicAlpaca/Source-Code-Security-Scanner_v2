function merge(target, source) {
  for (const key in source) {
    // ruleid: js-prototype-pollution
    target[key] = source[key];
  }
}

function deepMerge(obj, payload) {
  const key = payload.key;
  // ruleid: js-prototype-pollution
  obj[key] = payload.value;
}

// ok: js-prototype-pollution
const safe = Object.assign({}, source);
