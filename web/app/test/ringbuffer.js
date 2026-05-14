const test = require("node:test");
const assert = require("node:assert/strict");
const { sharedbuffer, ringbuffer } = require("../src/ringbuffer");

test("pop returns undefined when empty", () => {
  const rb = ringbuffer(sharedbuffer(4, 8, Uint8Array), 4, 8, Uint8Array);

  assert.equal(rb.pop(), undefined);
  assert.equal(rb.count(), 0);
});

test("push and pop preserve FIFO order", () => {
  const rb = ringbuffer(sharedbuffer(4, 8, Uint8Array), 4, 8, Uint8Array);
  const frames = [
    new Uint8Array([1, 2, 3, 4]),
    new Uint8Array([5, 6, 7, 8]),
    new Uint8Array([9, 10, 11, 12]),
  ];

  for (const frame of frames) {
    rb.push(frame);
  }

  for (const frame of frames) {
    assert.deepStrictEqual(rb.pop(), Array.from(frame));
  }

  assert.equal(rb.pop(), undefined);
});

test("overwrite keeps newest frames", () => {
  const rb = ringbuffer(sharedbuffer(2, 2, Uint8Array), 2, 2, Uint8Array);

  rb.push(new Uint8Array([1, 1]));
  rb.push(new Uint8Array([2, 2]));
  rb.push(new Uint8Array([3, 3]));
  rb.push(new Uint8Array([4, 4]));

  assert.deepStrictEqual(rb.pop(), [3, 3]);
  assert.deepStrictEqual(rb.pop(), [4, 4]);
  assert.equal(rb.pop(), undefined);
  assert.equal(rb.dropped_count(), 2);
});

test("float frames round-trip", () => {
  const rb = ringbuffer(sharedbuffer(3, 4, Float32Array), 3, 4, Float32Array);
  const frame = new Float32Array([1.25, 2.5, 3.75]);

  rb.push(frame);

  assert.deepStrictEqual(rb.pop(), Array.from(frame));
});
